package vault

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/lamb-systems/dottie/internal/model"
)

type payloadManifestCounts struct {
	entries        int
	plaintextBytes int64
}

func inspectPayloadManifest(payload []byte, limits Limits) (payloadManifestCounts, error) {
	input := bytes.NewReader(payload)
	archive := tar.NewReader(input)
	header, err := nextArchiveHeader(archive, input, 0, true)
	if err != nil || header == nil || header.Size < 0 {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	if header.Size > limits.MaxManifestBytes {
		return payloadManifestCounts{}, payloadInspectBound("MaxManifestBytes")
	}
	if err := checkHeader(header, manifestMember, header.Size); err != nil {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(archive, limits.MaxManifestBytes+1))
	if err != nil {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	if int64(len(manifestBytes)) > limits.MaxManifestBytes {
		return payloadManifestCounts{}, payloadInspectBound("MaxManifestBytes")
	}
	if int64(len(manifestBytes)) != header.Size {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	return inspectPayloadManifestJSON(manifestBytes, limits)
}

func inspectPayloadManifestJSON(data []byte, limits Limits) (payloadManifestCounts, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	var counts payloadManifestCounts
	seen := make(map[string]bool, 5)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return payloadManifestCounts{}, payloadInspectMalformed()
		}
		key, ok := keyToken.(string)
		if !ok || !payloadManifestField(key) || seen[key] {
			return payloadManifestCounts{}, payloadInspectMalformed()
		}
		seen[key] = true
		switch key {
		case "version":
			var value *uint32
			if err := decoder.Decode(&value); err != nil || value == nil {
				return payloadManifestCounts{}, payloadInspectMalformed()
			}
			if *value != Version {
				return payloadManifestCounts{}, payloadInspectUnsupported()
			}
		case "codec":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return payloadManifestCounts{}, payloadInspectMalformed()
			}
			if *value != CodecNone {
				return payloadManifestCounts{}, payloadInspectUnsupported()
			}
		case "snapshot_version":
			var value *uint32
			if err := decoder.Decode(&value); err != nil || value == nil {
				return payloadManifestCounts{}, payloadInspectMalformed()
			}
			if *value != model.SnapshotVersion {
				return payloadManifestCounts{}, payloadInspectUnsupported()
			}
		case "targets":
			if err := inspectPayloadTargets(decoder, limits); err != nil {
				return payloadManifestCounts{}, err
			}
		case "entries":
			if err := inspectPayloadEntries(decoder, limits, &counts); err != nil {
				return payloadManifestCounts{}, err
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	for _, field := range []string{"version", "codec", "snapshot_version", "targets", "entries"} {
		if !seen[field] {
			return payloadManifestCounts{}, payloadInspectMalformed()
		}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return payloadManifestCounts{}, payloadInspectMalformed()
	}
	return counts, nil
}

func payloadManifestField(name string) bool {
	switch name {
	case "version", "codec", "snapshot_version", "targets", "entries":
		return true
	default:
		return false
	}
}

func inspectPayloadTargets(decoder *json.Decoder, limits Limits) error {
	token, err := decoder.Token()
	if err != nil {
		return payloadInspectMalformed()
	}
	if token == nil {
		return nil
	}
	if token != json.Delim('[') {
		return payloadInspectMalformed()
	}
	previousID := ""
	for decoder.More() {
		var target model.Target
		if err := decoder.Decode(&target); err != nil {
			return payloadInspectMalformed()
		}
		if target.Root != nil {
			if err := checkPathBound(target.Root.Path, limits); err != nil {
				return payloadInspectBoundError(err)
			}
		}
		if err := target.Validate(); err != nil {
			return payloadInspectMalformed()
		}
		if previousID != "" && target.ID <= previousID {
			return payloadInspectMalformed()
		}
		previousID = target.ID
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return payloadInspectMalformed()
	}
	return nil
}

func inspectPayloadEntries(decoder *json.Decoder, limits Limits, counts *payloadManifestCounts) error {
	token, err := decoder.Token()
	if err != nil {
		return payloadInspectMalformed()
	}
	if token == nil {
		return nil
	}
	if token != json.Delim('[') {
		return payloadInspectMalformed()
	}
	var totalBytes int64
	for decoder.More() {
		if counts.entries >= limits.MaxEntries {
			return payloadInspectBound("MaxEntries")
		}
		var wire wireEntry
		if err := decoder.Decode(&wire); err != nil {
			return payloadInspectMalformed()
		}
		if err := checkPayloadWireBounds(wire, limits); err != nil {
			return payloadInspectBoundError(err)
		}
		if wire.Size > int64(^uint64(0)>>1)-totalBytes {
			return payloadInspectBound("MaxTotalBytes")
		}
		totalBytes += wire.Size
		if totalBytes > limits.MaxTotalBytes {
			return payloadInspectBound("MaxTotalBytes")
		}
		if wire.Source == model.SourceFiles && wire.State == string(model.FilePresent) && wire.Kind == model.FileRegular {
			if wire.Size > int64(^uint64(0)>>1)-counts.plaintextBytes {
				return payloadInspectBound("MaxTotalBytes")
			}
			counts.plaintextBytes += wire.Size
			if counts.plaintextBytes > limits.MaxTotalBytes {
				return payloadInspectBound("MaxTotalBytes")
			}
		}
		counts.entries++
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return payloadInspectMalformed()
	}
	return nil
}

func checkPayloadWireBounds(wire wireEntry, limits Limits) error {
	path := wirePath(wire)
	if err := checkPathBound(path, limits); err != nil {
		return err
	}
	if len(wire.LinkTarget) > limits.MaxPathBytes {
		return &BoundError{Kind: "MaxPathBytes"}
	}
	depthPath := path
	if wire.Source == model.SourceGNOME && path != "/" {
		depthPath = strings.Trim(path, "/")
	}
	depth := pathDepth(depthPath)
	if depth > limits.MaxDepth {
		return &BoundError{Kind: "MaxDepth"}
	}
	if wire.Size < 0 || wire.Size > limits.MaxEntryBytes {
		return &BoundError{Kind: "MaxEntryBytes"}
	}
	return nil
}

func payloadInspectBoundError(err error) error {
	var bound *BoundError
	if !errors.As(err, &bound) || !payloadBoundKind(bound.Kind) {
		return payloadInspectMalformed()
	}
	return payloadInspectBound(bound.Kind)
}
