package publicationstate

import (
	"bytes"
	"errors"
	"math"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/lamb-systems/dottie/internal/publication"
)

type validatedRecord struct {
	ref RecordReference
	raw []byte
}

type validatedObservation struct {
	blocks            []validatedRecord
	byCID             map[string]validatedRecord
	candidate         validatedRecord
	context           SuppliedContext
	setDigest         [32]byte
	observationDigest [32]byte
	observationID     [32]byte
	head              []byte
}

func validateBinding(binding Binding) error {
	if !utf8.ValidString(binding.AccountDID) || len(binding.AccountDID) == 0 || len(binding.AccountDID) > 2048 {
		return errors.New("binding")
	}
	did, err := syntax.ParseDID(binding.AccountDID)
	if err != nil || did.String() != binding.AccountDID || allZero(binding.Vault[:]) {
		return errors.New("binding")
	}
	switch binding.Backend {
	case BackendPublicRepo:
		if len(binding.Repository) > 8192 || binding.Repository != "at://"+binding.AccountDID {
			return errors.New("binding")
		}
	case BackendSpaces:
		if len(binding.Repository) > 8192 || !utf8.ValidString(binding.Repository) {
			return errors.New("binding")
		}
		uri, parseErr := syntax.ParseATURI(binding.Repository)
		if parseErr != nil || uri.String() != binding.Repository || string(uri.Authority()) != binding.AccountDID ||
			uri.Collection() == "" ||
			uri.RecordKey() == "" ||
			uri.Normalize().String() != binding.Repository {
			return errors.New("binding")
		}
	default:
		return errors.New("binding")
	}
	return nil
}

func validateAttemptLimits(limits AttemptLimits) error {
	defaults := DefaultAttemptLimits()
	values := []uint64{
		uint64(limits.ActiveAttempts),
		uint64(limits.HistoricalAttempts),
		uint64(limits.RetainedPublications),
		uint64(limits.ManagedObjects),
		limits.CustodyBytes,
		limits.MetadataBytes,
		limits.EvidenceBytes,
		limits.EvidenceSlotBytes,
		uint64(limits.LifecycleEvents),
		limits.EventBytes,
		limits.CoreBytes,
		uint64(limits.HistoryPageEntries),
		limits.HistoryPageBytes,
	}
	ceilings := []uint64{
		uint64(defaults.ActiveAttempts),
		uint64(defaults.HistoricalAttempts),
		uint64(defaults.RetainedPublications),
		uint64(defaults.ManagedObjects),
		defaults.CustodyBytes,
		defaults.MetadataBytes,
		defaults.EvidenceBytes,
		defaults.EvidenceSlotBytes,
		uint64(defaults.LifecycleEvents),
		defaults.EventBytes,
		defaults.CoreBytes,
		uint64(defaults.HistoryPageEntries),
		defaults.HistoryPageBytes,
	}
	for index, value := range values {
		if value == 0 || value > ceilings[index] || value > math.MaxInt64 {
			return errors.New("attempt limits")
		}
	}
	return nil
}

func validateLimits(limits Limits) error {
	defaults := DefaultLimits()
	values := []uint64{
		uint64(limits.SuppliedSnapshotCount),
		limits.SuppliedTotalBytes,
		uint64(limits.SuppliedContextBytes),
		uint64(limits.MaxLineageLinks),
		uint64(limits.CacheRecordCount),
		uint64(limits.CacheObservationCount),
		limits.CacheLogicalBytes,
		uint64(limits.AcceptedRecordCount),
		uint64(limits.AcceptedEventCount),
		limits.AcceptedLogicalBytes,
		uint64(limits.HistoryPageEvents),
		limits.HistoryEvidenceBytes,
	}
	ceilings := []uint64{
		uint64(defaults.SuppliedSnapshotCount),
		defaults.SuppliedTotalBytes,
		uint64(defaults.SuppliedContextBytes),
		uint64(defaults.MaxLineageLinks),
		uint64(defaults.CacheRecordCount),
		uint64(defaults.CacheObservationCount),
		defaults.CacheLogicalBytes,
		uint64(defaults.AcceptedRecordCount),
		uint64(defaults.AcceptedEventCount),
		defaults.AcceptedLogicalBytes,
		uint64(defaults.HistoryPageEvents),
		defaults.HistoryEvidenceBytes,
	}
	for index, value := range values {
		if value == 0 || value > ceilings[index] || value > math.MaxInt64 {
			return errors.New("limits")
		}
	}
	return nil
}

var errContextLimit = errors.New("context limit")

func validateContext(context SuppliedContext, binding Binding, limits Limits) error {
	if !utf8.ValidString(context.RepositoryRevision) || len(context.RepositoryRevision) == 0 ||
		len(context.RepositoryDigest) == 0 {
		return errors.New("context")
	}
	if len(context.RepositoryRevision) > 1024 || len(context.RepositoryDigest) > 128 {
		return errContextLimit
	}
	if binding.Backend == BackendSpaces {
		if context.Policy == nil || !context.Policy.OwnerOnly || !utf8.ValidString(context.Policy.Revision) ||
			len(context.Policy.Revision) == 0 ||
			len(context.Policy.Identity) == 0 {
			return errors.New("context")
		}
		if len(context.Policy.Revision) > 1024 || len(context.Policy.Identity) > 128 {
			return errContextLimit
		}
	} else if context.Policy != nil {
		return errors.New("context")
	}
	encoded, err := canonicalJSON(contextToWire(context))
	if err != nil {
		return errors.New("context")
	}
	if len(encoded) > int(limits.SuppliedContextBytes) {
		return errContextLimit
	}
	return nil
}

func validateObservation(input Observation, binding Binding, limits Limits) (validatedObservation, error) {
	return validateObservationWithManifest(input, binding, limits, false)
}

func validateFinalizationObservation(input Observation, binding Binding, limits Limits) (validatedObservation, error) {
	return validateObservationWithManifest(input, binding, limits, true)
}

func validateMaterialObservation(input Observation, binding Binding, limits Limits) (validatedObservation, error) {
	return validateObservationWithManifest(input, binding, limits, true)
}

func validateMaterialInput(
	input MaterialInput,
	observation validatedObservation,
	limits AttemptLimits,
) (materialAttachment, error) {
	record, err := publication.DecodeSnapshot(observation.candidate.raw)
	if err != nil {
		return materialAttachment{}, classified(ErrSchema, StageInput, ReasonCorrupt)
	}
	switch payloadFormOf(record) {
	case PayloadFormPacked:
		if len(input.Entries) != 0 {
			return materialAttachment{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if _, err := publication.DecodePayload(input.Payload, record.Blob); err != nil {
			return materialAttachment{}, err
		}
		return materialAttachment{
			form:    PayloadFormPacked,
			payload: input.Payload,
			blob:    record.Blob,
			name:    payloadBasename(input.Payload),
		}, nil
	case PayloadFormManifest:
		if len(input.Entries) == 0 {
			return materialAttachment{}, manifestPayloadUnsupported(StageInput)
		}
		if len(input.Payload) != 0 || len(input.Entries) != len(record.Entries) {
			return materialAttachment{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		for index, entry := range record.Entries {
			supplied := input.Entries[index]
			if supplied.Path != entry.Path || supplied.Mode != entry.Mode ||
				supplied.Size != entry.Size || uint64(len(supplied.Content)) != entry.Size {
				return materialAttachment{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
		}
		manifest := manifestPayloadOf(record)
		if err := validateManifestMaterialLimits(manifest, limits); err != nil {
			return materialAttachment{}, err
		}
		entries := make([]materialEntry, 0, len(record.Entries))
		for index, entry := range record.Entries {
			contentCID, err := publication.RawPayloadCID(input.Entries[index].Content)
			if err != nil || !bytes.Equal(contentCID, entry.Blob.CID) {
				return materialAttachment{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
			entries = append(entries, materialEntry{
				content: bytes.Clone(input.Entries[index].Content),
				blob: publication.BlobReference{
					CID:      bytes.Clone(entry.Blob.CID),
					Size:     entry.Size,
					MIMEType: entry.Blob.MIMEType,
				},
			})
		}
		return materialAttachment{form: PayloadFormManifest, manifest: manifest, entries: entries}, nil
	default:
		return materialAttachment{}, classified(ErrSchema, StageInput, ReasonCorrupt)
	}
}

func validateObservationWithManifest(input Observation, binding Binding, limits Limits, allowManifest bool) (validatedObservation, error) {
	if err := validateBinding(input.Origin); err != nil || !sameBinding(input.Origin, binding) {
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonBinding)
	}
	if err := validateContext(input.SuppliedContext, binding, limits); err != nil {
		if errors.Is(err, errContextLimit) {
			return validatedObservation{}, classified(ErrLimit, StageInput, ReasonContext)
		}
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonContext)
	}
	if len(input.Snapshots) == 0 || len(input.Head) == 0 {
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	if len(input.Snapshots) > int(limits.SuppliedSnapshotCount) {
		return validatedObservation{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	if len(input.Head) > publication.MaxRecordBytes {
		return validatedObservation{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	total := uint64(len(input.Head))
	if total > limits.SuppliedTotalBytes {
		return validatedObservation{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	blocks := make([]validatedRecord, 0, len(input.Snapshots))
	byCID := make(map[string]validatedRecord, len(input.Snapshots))
	publicBlocks := make([]SnapshotBlock, 0, len(input.Snapshots))
	var last uint64
	for index, block := range input.Snapshots {
		if len(block.Raw) == 0 || len(block.Key) != publication.SequenceKeyLength || !utf8.ValidString(block.Key) {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if len(block.Raw) > publication.MaxManifestRecordBytes {
			return validatedObservation{}, classified(ErrLimit, StageInput, ReasonRecordSet)
		}
		total += uint64(len(block.Raw))
		if total > limits.SuppliedTotalBytes {
			return validatedObservation{}, classified(ErrLimit, StageInput, ReasonRecordSet)
		}
		sequence, err := publication.ParseSequenceKey(block.Key)
		if err != nil || (index > 0 && sequence <= last) {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		last = sequence
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil || record.Vault != binding.Vault || record.PublicationSeq != sequence {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if payloadFormOf(record) == PayloadFormManifest && !allowManifest {
			return validatedObservation{}, manifestPayloadUnsupported(StageInput)
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		key := string(cid)
		if _, exists := byCID[key]; exists {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		ref := RecordReference{Key: block.Key, CID: bytes.Clone(cid), Sequence: sequence}
		validated := validatedRecord{ref: ref, raw: bytes.Clone(block.Raw)}
		blocks = append(blocks, validated)
		byCID[key] = validated
		publicBlocks = append(publicBlocks, SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)})
	}
	for _, block := range blocks {
		record, err := publication.DecodeSnapshot(block.raw)
		if err != nil {
			return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if len(record.Parent) == 0 {
			continue
		}
		if parent, ok := byCID[string(record.Parent)]; ok {
			if err := publication.VerifySuccessor(parent.raw, block.raw, block.ref.Key); err != nil {
				return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
		}
	}
	head, err := publication.DecodeHead(input.Head)
	if err != nil || head.Vault != binding.Vault {
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	var candidate validatedRecord
	found := false
	for _, block := range blocks {
		if block.ref.Sequence == head.PublicationSeq && bytes.Equal(block.ref.CID, head.SnapshotCID) {
			candidate = block
			found = true
			break
		}
	}
	if !found || publication.VerifyHeadBinding(input.Head, candidate.raw, candidate.ref.Key) != nil {
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	setDigest := makeSetDigest(publicBlocks)
	observationDigest, err := makeObservationDigest(input.Origin, input.SuppliedContext, input.Head, setDigest)
	if err != nil {
		return validatedObservation{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	id := domainHash("systems.lamb.dottie.local-observation-id.v1", observationDigest[:])
	return validatedObservation{
		blocks:            blocks,
		byCID:             byCID,
		candidate:         candidate,
		context:           cloneContext(input.SuppliedContext),
		setDigest:         setDigest,
		observationDigest: observationDigest,
		observationID:     id,
		head:              bytes.Clone(input.Head),
	}, nil
}

func sameBinding(a, b Binding) bool {
	return a.AccountDID == b.AccountDID && a.Backend == b.Backend && a.Repository == b.Repository && a.Vault == b.Vault
}

func cloneContext(context SuppliedContext) SuppliedContext {
	out := SuppliedContext{
		RepositoryRevision: context.RepositoryRevision,
		RepositoryDigest:   bytes.Clone(context.RepositoryDigest),
	}
	if context.Policy != nil {
		out.Policy = &Policy{
			Revision:  context.Policy.Revision,
			Identity:  bytes.Clone(context.Policy.Identity),
			OwnerOnly: context.Policy.OwnerOnly,
		}
	}
	return out
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
