package vault

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ipfs/go-cid"
	"golang.org/x/sys/unix"
)

const (
	ExportFormatVersion       uint32 = 1
	exportMagic                      = "DTVA"
	exportManifestMember             = "000000"
	maxExportManifestBytes           = 16 << 20
	maxExportEntryBytes              = int64(MaxEnvelopeBytes)
	maxExportArchiveBytes            = int64(2 << 30)
	maxExportEntries                 = 30000
	maxExportCertificates            = MaxRecipients
	maxExportLineagePositions        = 256
	maxExportRecoveryPoints          = 64
	maxExportOmissions               = 16
)

var (
	ErrUnsupportedExportVersion = errors.New("unsupported vault export format version")
	ErrIncompleteExport         = errors.New("incomplete vault export archive")
	ErrExportIntegrity          = errors.New("vault export integrity check failed")
	ErrForeignVault             = errors.New("vault export belongs to a different vault")
	ErrForeignAnchor            = errors.New("vault export belongs to a different trust anchor")
	ErrExportPolicy             = errors.New("vault export policy validation failed")
	ErrExportBlob               = errors.New("vault export is missing a referenced blob")
	ErrExportCaptureCheck       = errors.New("vault export requires a capture-selection predicate")
)

const (
	exportEntryPolicy              = "policy"
	exportEntryControl             = "control"
	exportEntryCertificate         = "certificate"
	exportEntryCheckpoint          = "checkpoint"
	exportEntryHead                = "head"
	exportEntryLineagePolicy       = "lineage_policy"
	exportEntryLineageControl      = "lineage_control"
	exportEntryLineageCertificate  = "lineage_certificate"
	exportEntryLineageHead         = "lineage_head"
	exportEntryRecoveryPolicy      = "recovery_policy"
	exportEntryRecoveryControl     = "recovery_control"
	exportEntryRecoveryCertificate = "recovery_certificate"
	exportEntryRecoveryHead        = "recovery_head"
	exportEntryBlob                = "blob"
)

const (
	exportLimitationNeverHeld = "Anything the vault never held locally is absent."
	exportLimitationScope     = "This archive contains only caller-supplied objects and blobs; it does not prove that the local inventory is complete."
	exportLimitationCAR       = "A repository CAR holds references, not payloads, and is not a complete blob backup."
)

type ExportPosition struct {
	Policy       []byte
	Control      []byte
	Certificates [][]byte
	Head         []byte
}

type ExportBlob struct {
	CID  []byte
	Data []byte
}

type ExportInput struct {
	VaultID           [32]byte
	AnchorFingerprint [32]byte
	Epoch             uint64
	PolicyDigest      [32]byte
	Current           ExportPosition
	Checkpoint        []byte
	Lineage           []ExportPosition
	RecoveryPoints    []ExportPosition
	Blobs             []ExportBlob
	Omissions         []ExportOmissionCode
	RecoveryKit       []byte
}

type ExportOmissionCode string

const (
	ExportOmissionUnavailableLocalHistory ExportOmissionCode = "unavailable-local-history"
	ExportOmissionUnretainedRecovery      ExportOmissionCode = "unretained-recovery"
	ExportOmissionUnavailableLocalBlobs   ExportOmissionCode = "unavailable-local-blobs"
)

type ExportEntry struct {
	Kind   string `json:"kind"`
	Group  uint32 `json:"group,omitempty"`
	CID    string `json:"cid,omitempty"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
	Member string `json:"member"`
}

type ExportManifest struct {
	FormatVersion     uint32               `json:"format_version"`
	VaultID           string               `json:"vault_id"`
	AnchorFingerprint string               `json:"anchor_fingerprint"`
	Epoch             uint64               `json:"epoch"`
	PolicyDigest      string               `json:"policy_digest"`
	Entries           []ExportEntry        `json:"entries"`
	Omissions         []ExportOmissionCode `json:"omissions"`
	Limitations       []string             `json:"limitations"`
}

type ExportArchive struct {
	Manifest       ExportManifest
	VaultID        [32]byte
	Anchor         [32]byte
	Epoch          uint64
	PolicyDigest   [32]byte
	Current        ExportPosition
	Checkpoint     []byte
	Lineage        []ExportPosition
	RecoveryPoints []ExportPosition
	Blobs          []ExportBlob
}

type ImportOptions struct {
	ExpectedVaultID [32]byte
	ExpectedAnchor  [32]byte
	AllowVaultMove  bool
	RecoveryKit     []byte
}

type exportMember struct {
	entry ExportEntry
	data  []byte
}

type exportCountingReader struct {
	reader io.Reader
	read   int64
}

func (reader *exportCountingReader) Read(data []byte) (int, error) {
	remaining := maxExportArchiveBytes - reader.read
	if remaining <= 0 {
		var probe [1]byte
		count, err := reader.reader.Read(probe[:])
		if count > 0 {
			return 0, fmt.Errorf("%w: archive size", ErrLimit)
		}
		return 0, err
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	count, err := reader.reader.Read(data)
	reader.read += int64(count)
	return count, err
}

func EncodeExportArchive(input ExportInput) ([]byte, error) {
	archive, err := archiveFromInput(input)
	if err != nil {
		return nil, err
	}
	members, err := exportMembers(archive)
	if err != nil {
		return nil, err
	}
	manifest := manifestForArchive(archive, members)
	manifestBytes, err := encodeExportManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode vault export manifest: %w", err)
	}
	if len(manifestBytes) > maxExportManifestBytes {
		return nil, fmt.Errorf("%w: manifest size", ErrLimit)
	}
	archiveSize := int64(len(exportMagic) + 1024)
	archiveSize += tarMemberSize(int64(len(manifestBytes)))
	for _, member := range members {
		archiveSize += tarMemberSize(int64(len(member.data)))
	}
	if archiveSize > maxExportArchiveBytes {
		return nil, fmt.Errorf("%w: archive size", ErrLimit)
	}
	var payload bytes.Buffer
	payload.Grow(int(archiveSize))
	payload.WriteString(exportMagic)
	writer := tar.NewWriter(&payload)
	if err := writeMember(writer, exportManifestMember, manifestBytes); err != nil {
		return nil, fmt.Errorf("write vault export manifest: %w", err)
	}
	for _, member := range members {
		if err := writeMember(writer, member.entry.Member, member.data); err != nil {
			return nil, fmt.Errorf("write vault export entry %q: %w", member.entry.Member, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish vault export archive: %w", err)
	}
	if int64(payload.Len()) > maxExportArchiveBytes {
		return nil, fmt.Errorf("%w: archive size", ErrLimit)
	}
	return bytes.Clone(payload.Bytes()), nil
}

func ReadExportArchive(reader io.Reader, options ImportOptions) (ExportArchive, error) {
	var magic [len(exportMagic)]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || string(magic[:]) != exportMagic {
		return ExportArchive{}, ErrIncompleteExport
	}
	input := &exportCountingReader{reader: reader, read: int64(len(magic))}
	tarReader := tar.NewReader(input)
	header, err := nextExportArchiveHeader(tarReader, input, 0, true)
	if err != nil {
		return ExportArchive{}, fmt.Errorf("%w: manifest header: %w", ErrIncompleteExport, err)
	}
	if header.Size < 0 || header.Size > maxExportManifestBytes {
		return ExportArchive{}, fmt.Errorf("%w: manifest size", ErrLimit)
	}
	if err := checkHeader(header, exportManifestMember, header.Size); err != nil {
		return ExportArchive{}, fmt.Errorf("%w: manifest header: %v", ErrIncompleteExport, err)
	}
	manifestBytes, err := readExportManifest(tarReader, header.Size)
	if err != nil {
		return ExportArchive{}, err
	}
	manifest, err := decodeExportManifest(manifestBytes)
	if err != nil {
		return ExportArchive{}, err
	}
	members, err := readExportMembers(tarReader, input, manifest)
	if err != nil {
		return ExportArchive{}, err
	}
	archive, err := archiveFromManifest(manifest, members)
	if err != nil {
		return ExportArchive{}, err
	}
	if err := validateExportBinding(archive, options); err != nil {
		return ExportArchive{}, err
	}
	if err := validateExportSignatures(archive, options.RecoveryKit); err != nil {
		return ExportArchive{}, err
	}
	return archive, nil
}

func readExportManifest(tarReader *tar.Reader, size int64) ([]byte, error) {
	var prefix bytes.Buffer
	probeLimit := size
	if probeLimit > 512 {
		probeLimit = 512
	}
	decoder := json.NewDecoder(io.TeeReader(io.LimitReader(tarReader, probeLimit), &prefix))
	if err := probeExportManifestVersion(decoder); err != nil {
		return nil, err
	}
	if int64(prefix.Len()) > size {
		return nil, fmt.Errorf("%w: manifest length", ErrIncompleteExport)
	}
	remaining := size - int64(prefix.Len())
	rest, err := io.ReadAll(io.LimitReader(tarReader, remaining+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read manifest: %v", ErrIncompleteExport, err)
	}
	if int64(prefix.Len()+len(rest)) != size {
		return nil, fmt.Errorf("%w: manifest length", ErrIncompleteExport)
	}
	return append(prefix.Bytes(), rest...), nil
}

func probeExportManifestVersion(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: manifest is not JSON", ErrIncompleteExport)
	}
	key, err := decoder.Token()
	if err != nil || key != "format_version" {
		return fmt.Errorf("%w: manifest format version is absent or not first", ErrIncompleteExport)
	}
	var version uint32
	if err := decoder.Decode(&version); err != nil {
		return fmt.Errorf("%w: manifest format version is malformed", ErrIncompleteExport)
	}
	if version != ExportFormatVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedExportVersion, version)
	}
	return nil
}

func WriteExportArchive(path string, input ExportInput, isCaptured func(string) (bool, error)) error {
	if isCaptured == nil {
		return ErrExportCaptureCheck
	}
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("export destination must be an absolute path")
	}
	absolute := filepath.Clean(path)
	parent := filepath.Dir(absolute)
	name := filepath.Base(absolute)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return errors.New("export destination directory cannot be resolved")
	}
	resolved := filepath.Join(resolvedParent, name)
	captured, err := isCaptured(resolved)
	if err != nil {
		return fmt.Errorf("cannot check export destination against capture selections: %w", err)
	}
	if captured {
		return errors.New("export destination is inside a capture selection")
	}
	directoryFD, err := unix.Open(resolvedParent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open export directory: %w", err)
	}
	defer unix.Close(directoryFD)
	var pinnedStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &pinnedStat); err != nil {
		return fmt.Errorf("inspect export directory: %w", err)
	}
	if err := inspectExportDestinationAt(directoryFD, name); err != nil {
		return err
	}
	encoded, err := EncodeExportArchive(input)
	if err != nil {
		return err
	}
	currentParent, err := verifyPinnedExportDirectory(parent, pinnedStat)
	if err != nil {
		return err
	}
	resolved = filepath.Join(currentParent, name)
	captured, err = isCaptured(resolved)
	if err != nil {
		return fmt.Errorf("cannot recheck export destination against capture selections: %w", err)
	}
	if captured {
		return errors.New("export destination is inside a capture selection")
	}
	if _, err := verifyPinnedExportDirectory(parent, pinnedStat); err != nil {
		return err
	}
	if err := inspectExportDestinationAt(directoryFD, name); err != nil {
		return err
	}
	temporary, file, err := createExportTemporary(directoryFD)
	if err != nil {
		return fmt.Errorf("create temporary export: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary export: %w", writeErr)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary export: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary export: %w", err)
	}
	if err := unix.Renameat(directoryFD, temporary, directoryFD, name); err != nil {
		return fmt.Errorf("publish export file: %w", err)
	}
	committed = true
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync export directory: %w", err)
	}
	return nil
}

func verifyPinnedExportDirectory(parent string, pinnedStat unix.Stat_t) (string, error) {
	currentParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", errors.New("export destination directory changed during encoding")
	}
	var currentStat unix.Stat_t
	if err := unix.Stat(currentParent, &currentStat); err != nil || currentStat.Dev != pinnedStat.Dev || currentStat.Ino != pinnedStat.Ino {
		return "", errors.New("export destination directory changed during encoding")
	}
	return currentParent, nil
}

func inspectExportDestinationAt(directoryFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect export destination")
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return errors.New("export destination cannot be a symbolic link")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("export destination is not a regular file")
	}
	return nil
}

func createExportTemporary(directoryFD int) (string, *os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		token := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, token); err != nil {
			return "", nil, err
		}
		name := ".dottie-export-" + hex.EncodeToString(token)
		fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, os.NewFile(uintptr(fd), name), nil
	}
	return "", nil, errors.New("cannot allocate a unique temporary export name")
}

func archiveFromInput(input ExportInput) (ExportArchive, error) {
	if input.VaultID == ([32]byte{}) || input.AnchorFingerprint == ([32]byte{}) || input.PolicyDigest == ([32]byte{}) || len(input.RecoveryKit) != 32 {
		return ExportArchive{}, fmt.Errorf("%w: required archive identity or recovery kit", ErrFormat)
	}
	archive := ExportArchive{
		VaultID: input.VaultID, Anchor: input.AnchorFingerprint, Epoch: input.Epoch,
		PolicyDigest: input.PolicyDigest, Current: input.Current, Checkpoint: input.Checkpoint,
		Lineage: input.Lineage, RecoveryPoints: input.RecoveryPoints, Blobs: input.Blobs,
	}
	omissions := append([]ExportOmissionCode(nil), input.Omissions...)
	sort.Slice(omissions, func(i, j int) bool { return omissions[i] < omissions[j] })
	archive.Manifest = ExportManifest{
		FormatVersion: ExportFormatVersion, VaultID: hex.EncodeToString(archive.VaultID[:]),
		AnchorFingerprint: hex.EncodeToString(archive.Anchor[:]), Epoch: archive.Epoch,
		PolicyDigest: hex.EncodeToString(archive.PolicyDigest[:]), Omissions: omissions,
		Limitations: []string{exportLimitationNeverHeld, exportLimitationScope, exportLimitationCAR},
	}
	if err := validateManifestMetadata(archive.Manifest); err != nil {
		return ExportArchive{}, err
	}
	if err := validateExportSignatures(archive, input.RecoveryKit); err != nil {
		return ExportArchive{}, err
	}
	return archive, nil
}

func validateExportBinding(archive ExportArchive, options ImportOptions) error {
	if options.ExpectedVaultID == ([32]byte{}) || options.ExpectedAnchor == ([32]byte{}) || len(options.RecoveryKit) != 32 {
		return fmt.Errorf("%w: expected vault, anchor, and recovery kit are required", ErrAuthorization)
	}
	if archive.VaultID != options.ExpectedVaultID && !options.AllowVaultMove {
		return fmt.Errorf("%w: archive vault ID does not match the requested vault", ErrForeignVault)
	}
	if archive.Anchor != options.ExpectedAnchor {
		return ErrForeignAnchor
	}
	return nil
}

func validateExportSignatures(archive ExportArchive, kit []byte) error {
	if archive.VaultID == ([32]byte{}) || archive.Anchor == ([32]byte{}) || len(kit) != 32 {
		return fmt.Errorf("%w: archive identity or recovery kit", ErrAuthorization)
	}
	positions := make([]ExportPosition, 0, 1+len(archive.Lineage)+len(archive.RecoveryPoints))
	positions = append(positions, archive.Current)
	positions = append(positions, archive.Lineage...)
	positions = append(positions, archive.RecoveryPoints...)
	if len(archive.Lineage) > maxExportLineagePositions || len(archive.RecoveryPoints) > maxExportRecoveryPoints {
		return fmt.Errorf("%w: position count", ErrLimit)
	}
	currentPolicy, err := validateExportPosition(archive.VaultID, archive.Anchor, archive.Current)
	if err != nil {
		return fmt.Errorf("%w: current position: %v", ErrExportPolicy, err)
	}
	if currentPolicy.EpochSeq != archive.Epoch || mustPolicyDigest(archive.Current.Policy) != archive.PolicyDigest {
		return fmt.Errorf("%w: manifest epoch or policy digest does not match current position", ErrExportPolicy)
	}
	if currentPolicy.RecoveryAnchor != archive.Anchor {
		return fmt.Errorf("%w: policy recovery anchor differs from manifest", ErrExportPolicy)
	}
	positionControls := make(map[string]Control, len(positions))
	positionByControl := make(map[string]ExportPosition, len(positions))
	for index, position := range positions {
		if index == 0 {
			continue
		}
		if _, err := validateExportPosition(archive.VaultID, archive.Anchor, position); err != nil {
			return fmt.Errorf("%w: history position %d: %v", ErrExportPolicy, index, err)
		}
	}
	for _, position := range positions {
		control, _, err := verifyControlEvidence(archive.VaultID, archive.Anchor, ControlEvidence{
			Control: position.Control, Policy: position.Policy, Certificates: position.Certificates,
		})
		if err != nil {
			return fmt.Errorf("%w: control evidence: %v", ErrExportPolicy, err)
		}
		controlCID, err := rawCID(position.Control)
		if err != nil {
			return fmt.Errorf("%w: control CID", ErrExportPolicy)
		}
		positionControls[string(controlCID)] = control
		positionByControl[string(controlCID)] = position
	}
	kitPublic, err := RecoveryKitSigningPublicKey(kit, archive.VaultID)
	if err != nil {
		return fmt.Errorf("%w: recovery kit key", ErrAuthorization)
	}
	checkpoint, err := VerifyCheckpoint(archive.Checkpoint, kitPublic)
	if err != nil {
		return fmt.Errorf("%w: checkpoint signature: %v", ErrAuthorization, err)
	}
	if checkpoint.Vault != archive.VaultID || checkpoint.Anchor != archive.Anchor {
		return fmt.Errorf("%w: checkpoint vault or anchor", ErrAuthorization)
	}
	checkpointControl, exists := positionControls[string(checkpoint.ControlCID)]
	if !exists || checkpointControl.EpochSeq != checkpoint.EpochSeq || checkpointControl.PolicyDigest != checkpoint.PolicyDigest || !bytes.Equal(checkpointControl.HeadSnapshotCID, checkpoint.SnapshotCID) {
		return fmt.Errorf("%w: checkpoint position is absent or does not match signed control evidence", ErrAuthorization)
	}
	if err := validateExportAncestry(archive.Current, checkpoint.ControlCID, positionByControl); err != nil {
		return err
	}
	if len(checkpoint.SnapshotCID) > 0 {
		if _, err := cid.Cast(checkpoint.SnapshotCID); err != nil {
			return fmt.Errorf("%w: checkpoint snapshot CID", ErrAuthorization)
		}
		checkpointSnapshotFound := false
		for _, position := range positions {
			controlCID, err := rawCID(position.Control)
			if err != nil || !bytes.Equal(controlCID, checkpoint.ControlCID) || len(position.Head) == 0 {
				continue
			}
			head, err := DecodeHead(position.Head)
			if err == nil && bytes.Equal(head.SnapshotCID, checkpoint.SnapshotCID) {
				checkpointSnapshotFound = true
				break
			}
		}
		if !checkpointSnapshotFound {
			return fmt.Errorf("%w: %s", ErrExportBlob, exportCIDName(checkpoint.SnapshotCID))
		}
	}
	blobByCID := make(map[string]ExportBlob, len(archive.Blobs))
	usedBlobs := make(map[string]bool, len(archive.Blobs))
	for _, blob := range archive.Blobs {
		actualCID, err := rawCID(blob.Data)
		if err != nil || !bytes.Equal(actualCID, blob.CID) {
			return fmt.Errorf("%w: blob CID does not match its payload", ErrExportIntegrity)
		}
		key := string(blob.CID)
		if _, duplicate := blobByCID[key]; duplicate {
			return fmt.Errorf("%w: duplicate blob CID", ErrExportIntegrity)
		}
		blobByCID[key] = blob
	}
	for _, position := range positions {
		if len(position.Head) == 0 {
			continue
		}
		policy, err := DecodePolicy(position.Policy)
		if err != nil {
			return fmt.Errorf("%w: position policy", ErrExportPolicy)
		}
		control, err := DecodeControl(position.Control)
		if err != nil {
			return fmt.Errorf("%w: position control", ErrExportPolicy)
		}
		head, err := DecodeHead(position.Head)
		if err != nil {
			return fmt.Errorf("%w: position head", ErrExportPolicy)
		}
		if !bytes.Equal(head.BlobCID, head.SnapshotCID) || head.PublicationCount == 0 && !bytes.Equal(control.HeadSnapshotCID, head.SnapshotCID) {
			return fmt.Errorf("%w: head/control snapshot linkage", ErrExportPolicy)
		}
		if head.PublicationCount > uint64(policy.MaxPublications) {
			return fmt.Errorf("%w: head publication count exceeds policy maximum", ErrExportPolicy)
		}
		cidValue, err := cid.Cast(head.BlobCID)
		if err != nil {
			return fmt.Errorf("%w: invalid blob CID in head", ErrExportPolicy)
		}
		blobKey := string(head.BlobCID)
		blob, exists := blobByCID[blobKey]
		if !exists {
			return fmt.Errorf("%w: %s", ErrExportBlob, cidValue.String())
		}
		usedBlobs[blobKey] = true
		envelope, err := DecodeEnvelope(blob.Data)
		if err != nil {
			return fmt.Errorf("%w: referenced snapshot %s: %v", ErrExportPolicy, cidValue.String(), err)
		}
		if envelope.Purpose != PurposeSnapshot || envelope.Vault != policy.Vault || envelope.EpochSeq != policy.EpochSeq || envelope.PolicyDigest != mustPolicyDigest(position.Policy) || !bytes.Equal(envelope.Parent, head.PrevHeadCID) || envelope.DeviceID != head.Signer.DeviceID || !bytes.Equal(envelope.KeyID, head.Signer.KeyID) {
			return fmt.Errorf("%w: referenced snapshot metadata", ErrExportPolicy)
		}
		predecessor := Predecessor{
			ControlCID: mustRawCID(position.Control), PolicyDigest: mustPolicyDigest(position.Policy), EpochSeq: policy.EpochSeq,
			HeadCID: bytes.Clone(head.SnapshotCID), Head: bytes.Clone(position.Head), Control: bytes.Clone(position.Control),
			Policy: bytes.Clone(position.Policy), Certificates: cloneByteSlices(position.Certificates), TrustAnchor: archive.Anchor,
		}
		signer, err := validatePublicationSigner(predecessor, policy, control, envelope.DeviceID, envelope.KeyID)
		if err != nil {
			return fmt.Errorf("%w: snapshot signer", ErrExportPolicy)
		}
		publication := Publication{Head: position.Head, Snapshot: blob.Data}
		if err := verifyHeadAndEnvelopeSignatures(publication, head, envelope, signer); err != nil {
			return fmt.Errorf("%w: head or snapshot signature: %v", ErrExportPolicy, err)
		}
		if !publicationRecipientsMatch(policy, envelope) {
			return fmt.Errorf("%w: snapshot recipients", ErrExportPolicy)
		}
	}
	if err := validateExportHeadAncestry(positions); err != nil {
		return err
	}
	if len(usedBlobs) != len(blobByCID) {
		return fmt.Errorf("%w: archive contains an unreferenced blob", ErrExportIntegrity)
	}
	return nil
}

func validateExportHeadAncestry(positions []ExportPosition) error {
	for _, position := range positions {
		if len(position.Head) == 0 {
			continue
		}
		control, err := DecodeControl(position.Control)
		if err != nil {
			return fmt.Errorf("%w: head history control", ErrExportPolicy)
		}
		head, err := DecodeHead(position.Head)
		if err != nil {
			return fmt.Errorf("%w: head history head", ErrExportPolicy)
		}
		if head.PublicationCount == 0 {
			continue
		}
		predecessorFound := false
		for _, candidate := range positions {
			if len(candidate.Head) == 0 || !bytes.Equal(candidate.Control, position.Control) {
				continue
			}
			predecessorHead, err := DecodeHead(candidate.Head)
			if err == nil && bytes.Equal(predecessorHead.SnapshotCID, head.PrevHeadCID) && predecessorHead.PublicationCount+1 == head.PublicationCount {
				predecessorFound = true
				break
			}
		}
		if len(head.PrevHeadCID) == 0 {
			return fmt.Errorf("%w: publication head has no predecessor CID", ErrExportPolicy)
		}
		if _, err := cid.Cast(head.PrevHeadCID); err != nil {
			return fmt.Errorf("%w: publication head predecessor CID", ErrExportPolicy)
		}
		if !predecessorFound {
			return fmt.Errorf("%w: missing publication head predecessor %s", ErrExportBlob, exportCIDName(head.PrevHeadCID))
		}
		if control.PolicyDigest != mustPolicyDigest(position.Policy) {
			return fmt.Errorf("%w: publication head policy linkage", ErrExportPolicy)
		}
	}
	return nil
}

func validateExportAncestry(current ExportPosition, checkpointCID []byte, positions map[string]ExportPosition) error {
	currentCID, err := rawCID(current.Control)
	if err != nil {
		return fmt.Errorf("%w: current control CID", ErrExportPolicy)
	}
	visited := make(map[string]bool, len(positions))
	for links := 0; links <= len(positions); links++ {
		if bytes.Equal(currentCID, checkpointCID) {
			return nil
		}
		key := string(currentCID)
		if visited[key] {
			return fmt.Errorf("%w: control ancestry contains a cycle", ErrExportPolicy)
		}
		visited[key] = true
		position, exists := positions[key]
		if !exists {
			return fmt.Errorf("%w: control position %s is absent", ErrIncompleteExport, exportCIDName(currentCID))
		}
		control, err := DecodeControl(position.Control)
		if err != nil {
			return fmt.Errorf("%w: control ancestry object", ErrExportPolicy)
		}
		policy, err := DecodePolicy(position.Policy)
		if err != nil {
			return fmt.Errorf("%w: policy ancestry object", ErrExportPolicy)
		}
		if len(control.PrevControlCID) == 0 {
			return fmt.Errorf("%w: checkpoint is not an ancestor of current control", ErrExportPolicy)
		}
		predecessor, exists := positions[string(control.PrevControlCID)]
		if !exists {
			return fmt.Errorf("%w: missing control predecessor %s", ErrIncompleteExport, exportCIDName(control.PrevControlCID))
		}
		predecessorPolicy, err := DecodePolicy(predecessor.Policy)
		if err != nil {
			return fmt.Errorf("%w: policy predecessor object", ErrExportPolicy)
		}
		if policy.PrevPolicyDigest != mustPolicyDigest(predecessor.Policy) {
			return fmt.Errorf("%w: policy predecessor digest does not match control ancestry", ErrExportPolicy)
		}
		if predecessorPolicy.Vault != policy.Vault || predecessorPolicy.EpochSeq == ^uint64(0) || predecessorPolicy.EpochSeq+1 != policy.EpochSeq {
			return fmt.Errorf("%w: policy ancestry does not advance by one epoch", ErrExportPolicy)
		}
		currentCID = bytes.Clone(control.PrevControlCID)
	}
	return fmt.Errorf("%w: control ancestry exceeds supplied positions", ErrExportPolicy)
}

func exportCIDName(encoded []byte) string {
	value, err := cid.Cast(encoded)
	if err != nil {
		return hex.EncodeToString(encoded)
	}
	return value.String()
}

func validateExportPosition(vaultID, anchor [32]byte, position ExportPosition) (Policy, error) {
	if len(position.Policy) == 0 || len(position.Control) == 0 || len(position.Certificates) == 0 || len(position.Certificates) > maxExportCertificates {
		return Policy{}, fmt.Errorf("%w: missing policy, control or certificate set", ErrIncompleteExport)
	}
	control, _, err := verifyControlEvidence(vaultID, anchor, ControlEvidence{
		Control: position.Control, Policy: position.Policy, Certificates: position.Certificates,
	})
	if err != nil {
		return Policy{}, err
	}
	policy, err := DecodePolicy(position.Policy)
	if err != nil {
		return Policy{}, err
	}
	if policy.RecoveryAnchor != anchor || policy.Vault != vaultID || policy.EpochSeq != control.EpochSeq {
		return Policy{}, ErrAuthorization
	}
	policyDigest, err := ComputePolicyDigest(position.Policy)
	if err != nil || control.PolicyDigest != policyDigest {
		return Policy{}, ErrAuthorization
	}
	predecessor := Predecessor{
		ControlCID: mustRawCID(position.Control), PolicyDigest: policyDigest, EpochSeq: policy.EpochSeq,
		HeadCID: bytes.Clone(control.HeadSnapshotCID), Control: bytes.Clone(position.Control), Policy: bytes.Clone(position.Policy),
		Certificates: cloneByteSlices(position.Certificates), TrustAnchor: anchor,
	}
	if err := validatePublicationRecipients(predecessor, policy); err != nil {
		return Policy{}, err
	}
	if len(control.HeadSnapshotCID) == 0 {
		if len(position.Head) != 0 {
			return Policy{}, errors.New("head supplied for control without a snapshot")
		}
		return policy, nil
	}
	if len(position.Head) == 0 {
		return Policy{}, fmt.Errorf("%w: control references a head but none was supplied", ErrIncompleteExport)
	}
	predecessor.Head = bytes.Clone(position.Head)
	head, err := DecodeHead(position.Head)
	if err != nil {
		return Policy{}, err
	}
	predecessor.HeadCID = bytes.Clone(head.SnapshotCID)
	_, err = currentHeadForPublication(predecessor, policy, control)
	if err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func exportMembers(archive ExportArchive) ([]exportMember, error) {
	var members []exportMember
	add := func(kind string, group uint32, data, blobCID []byte) error {
		if len(data) == 0 {
			return fmt.Errorf("%w: empty %s object", ErrIncompleteExport, kind)
		}
		if int64(len(data)) > maxExportEntryBytes {
			return fmt.Errorf("%w: entry size", ErrLimit)
		}
		entry := ExportEntry{Kind: kind, Group: group, Length: int64(len(data)), SHA256: exportDigest(data)}
		if kind == exportEntryBlob {
			cidValue, err := cid.Cast(blobCID)
			if err != nil {
				return fmt.Errorf("%w: invalid blob CID", ErrFormat)
			}
			entry.CID = cidValue.String()
		}
		entry.Member = ordinal(len(members) + 1)
		members = append(members, exportMember{entry: entry, data: data})
		return nil
	}
	if err := add(exportEntryPolicy, 0, archive.Current.Policy, nil); err != nil {
		return nil, err
	}
	if err := add(exportEntryControl, 0, archive.Current.Control, nil); err != nil {
		return nil, err
	}
	for _, certificate := range sortedCertificates(archive.Current.Certificates) {
		if err := add(exportEntryCertificate, 0, certificate, nil); err != nil {
			return nil, err
		}
	}
	if err := add(exportEntryCheckpoint, 0, archive.Checkpoint, nil); err != nil {
		return nil, err
	}
	if len(archive.Current.Head) > 0 {
		if err := add(exportEntryHead, 0, archive.Current.Head, nil); err != nil {
			return nil, err
		}
	}
	lineage := sortedExportPositions(archive.Lineage)
	for index, position := range lineage {
		group := uint32(index + 1)
		if err := add(exportEntryLineagePolicy, group, position.Policy, nil); err != nil {
			return nil, err
		}
		if err := add(exportEntryLineageControl, group, position.Control, nil); err != nil {
			return nil, err
		}
		for _, certificate := range sortedCertificates(position.Certificates) {
			if err := add(exportEntryLineageCertificate, group, certificate, nil); err != nil {
				return nil, err
			}
		}
		if len(position.Head) > 0 {
			if err := add(exportEntryLineageHead, group, position.Head, nil); err != nil {
				return nil, err
			}
		}
	}
	recovery := sortedExportPositions(archive.RecoveryPoints)
	for index, position := range recovery {
		group := uint32(index + 1)
		if err := add(exportEntryRecoveryPolicy, group, position.Policy, nil); err != nil {
			return nil, err
		}
		if err := add(exportEntryRecoveryControl, group, position.Control, nil); err != nil {
			return nil, err
		}
		for _, certificate := range sortedCertificates(position.Certificates) {
			if err := add(exportEntryRecoveryCertificate, group, certificate, nil); err != nil {
				return nil, err
			}
		}
		if len(position.Head) > 0 {
			if err := add(exportEntryRecoveryHead, group, position.Head, nil); err != nil {
				return nil, err
			}
		}
	}
	blobs := append([]ExportBlob(nil), archive.Blobs...)
	sort.Slice(blobs, func(i, j int) bool { return bytes.Compare(blobs[i].CID, blobs[j].CID) < 0 })
	for _, blob := range blobs {
		if err := add(exportEntryBlob, 0, blob.Data, blob.CID); err != nil {
			return nil, err
		}
	}
	if len(members) > maxExportEntries {
		return nil, fmt.Errorf("%w: entry count", ErrLimit)
	}
	return members, nil
}

func manifestForArchive(archive ExportArchive, members []exportMember) ExportManifest {
	manifest := archive.Manifest
	manifest.Entries = make([]ExportEntry, len(members))
	for index := range members {
		manifest.Entries[index] = members[index].entry
	}
	return manifest
}

func readExportMembers(tarReader *tar.Reader, input *exportCountingReader, manifest ExportManifest) ([]exportMember, error) {
	if len(manifest.Entries) == 0 || len(manifest.Entries) > maxExportEntries {
		return nil, fmt.Errorf("%w: invalid entry inventory", ErrIncompleteExport)
	}
	members := make([]exportMember, 0, len(manifest.Entries))
	var previousSize int64 = manifestHeaderSize(manifest)
	var total int64
	for index, entry := range manifest.Entries {
		if entry.Member != ordinal(index+1) || entry.Length < 0 || entry.Length > maxExportEntryBytes || len(entry.SHA256) != sha256.Size*2 {
			return nil, fmt.Errorf("%w: malformed entry inventory", ErrExportIntegrity)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil || strings.ToLower(entry.SHA256) != entry.SHA256 {
			return nil, fmt.Errorf("%w: invalid entry digest", ErrExportIntegrity)
		}
		if entry.Kind == exportEntryBlob {
			cidValue, err := cid.Decode(entry.CID)
			if err != nil || cidValue.String() != entry.CID {
				return nil, fmt.Errorf("%w: invalid blob CID metadata", ErrExportIntegrity)
			}
		} else if entry.CID != "" {
			return nil, fmt.Errorf("%w: CID on non-blob entry", ErrExportIntegrity)
		}
		header, err := nextExportArchiveHeader(tarReader, input, previousSize, false)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %q: %w", ErrIncompleteExport, entry.Member, err)
		}
		if err := checkHeader(header, entry.Member, entry.Length); err != nil {
			return nil, fmt.Errorf("%w: entry header: %v", ErrExportIntegrity, err)
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, maxExportEntryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: read entry %q: %w", ErrExportIntegrity, entry.Member, err)
		}
		if int64(len(data)) != entry.Length {
			return nil, fmt.Errorf("%w: entry length mismatch", ErrExportIntegrity)
		}
		previousSize = header.Size
		total += int64(len(data))
		if total > maxExportArchiveBytes {
			return nil, fmt.Errorf("%w: total entry size", ErrLimit)
		}
		if exportDigest(data) != entry.SHA256 {
			return nil, fmt.Errorf("%w: digest mismatch for entry %q", ErrExportIntegrity, entry.Member)
		}
		members = append(members, exportMember{entry: entry, data: data})
	}
	if _, err := nextExportArchiveHeader(tarReader, input, previousSize, false); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: unexpected archive member", ErrExportIntegrity)
		}
		return nil, fmt.Errorf("%w: archive framing: %w", ErrExportIntegrity, err)
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: trailing archive data", ErrExportIntegrity)
	}
	return members, nil
}

func nextExportArchiveHeader(archive *tar.Reader, input *exportCountingReader, previousSize int64, first bool) (*tar.Header, error) {
	before := input.read
	header, err := archive.Next()
	if errors.Is(err, ErrLimit) {
		return nil, err
	}
	consumed := input.read - before
	expected := int64(blockPadding(previousSize) + 512)
	if first {
		expected = 512
	} else if errors.Is(err, io.EOF) {
		expected = int64(blockPadding(previousSize) + 1024)
	}
	if consumed != expected {
		return nil, fmt.Errorf("noncanonical tar framing: consumed %d bytes between members, want %d", consumed, expected)
	}
	return header, err
}

func archiveFromManifest(manifest ExportManifest, members []exportMember) (ExportArchive, error) {
	if err := validateManifestMetadata(manifest); err != nil {
		return ExportArchive{}, err
	}
	vaultBytes, _ := hex.DecodeString(manifest.VaultID)
	anchorBytes, _ := hex.DecodeString(manifest.AnchorFingerprint)
	digestBytes, _ := hex.DecodeString(manifest.PolicyDigest)
	archive := ExportArchive{Manifest: manifest, Epoch: manifest.Epoch}
	copy(archive.VaultID[:], vaultBytes)
	copy(archive.Anchor[:], anchorBytes)
	copy(archive.PolicyDigest[:], digestBytes)
	positions := map[string]map[uint32]*ExportPosition{
		"lineage": {}, "recovery": {},
	}
	certificateGroups := make(map[uint32][][]byte)
	lineageCertificateGroups := make(map[uint32][][]byte)
	recoveryCertificateGroups := make(map[uint32][][]byte)
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		key := fmt.Sprintf("%s:%d", member.entry.Kind, member.entry.Group)
		if member.entry.Kind != exportEntryCertificate && member.entry.Kind != exportEntryLineageCertificate && member.entry.Kind != exportEntryRecoveryCertificate && member.entry.Kind != exportEntryBlob {
			if seen[key] {
				return ExportArchive{}, fmt.Errorf("%w: duplicate object entry", ErrExportIntegrity)
			}
			seen[key] = true
		}
		switch member.entry.Kind {
		case exportEntryPolicy:
			if member.entry.Group != 0 {
				return ExportArchive{}, ErrExportIntegrity
			}
			archive.Current.Policy = member.data
		case exportEntryControl:
			if member.entry.Group != 0 {
				return ExportArchive{}, ErrExportIntegrity
			}
			archive.Current.Control = member.data
		case exportEntryCertificate:
			if member.entry.Group != 0 {
				return ExportArchive{}, ErrExportIntegrity
			}
			certificateGroups[0] = append(certificateGroups[0], member.data)
		case exportEntryCheckpoint:
			if member.entry.Group != 0 {
				return ExportArchive{}, ErrExportIntegrity
			}
			archive.Checkpoint = member.data
		case exportEntryHead:
			if member.entry.Group != 0 {
				return ExportArchive{}, ErrExportIntegrity
			}
			archive.Current.Head = member.data
		case exportEntryLineagePolicy, exportEntryLineageControl, exportEntryLineageCertificate, exportEntryLineageHead:
			if member.entry.Group == 0 {
				return ExportArchive{}, fmt.Errorf("%w: invalid lineage group", ErrExportIntegrity)
			}
			position := ensureExportPosition(positions["lineage"], member.entry.Group)
			switch member.entry.Kind {
			case exportEntryLineagePolicy:
				position.Policy = member.data
			case exportEntryLineageControl:
				position.Control = member.data
			case exportEntryLineageCertificate:
				lineageCertificateGroups[member.entry.Group] = append(lineageCertificateGroups[member.entry.Group], member.data)
			case exportEntryLineageHead:
				position.Head = member.data
			}
		case exportEntryRecoveryPolicy, exportEntryRecoveryControl, exportEntryRecoveryCertificate, exportEntryRecoveryHead:
			if member.entry.Group == 0 {
				return ExportArchive{}, fmt.Errorf("%w: invalid recovery group", ErrExportIntegrity)
			}
			position := ensureExportPosition(positions["recovery"], member.entry.Group)
			switch member.entry.Kind {
			case exportEntryRecoveryPolicy:
				position.Policy = member.data
			case exportEntryRecoveryControl:
				position.Control = member.data
			case exportEntryRecoveryCertificate:
				recoveryCertificateGroups[member.entry.Group] = append(recoveryCertificateGroups[member.entry.Group], member.data)
			case exportEntryRecoveryHead:
				position.Head = member.data
			}
		case exportEntryBlob:
			cidValue, _ := cid.Decode(member.entry.CID)
			archive.Blobs = append(archive.Blobs, ExportBlob{CID: bytes.Clone(cidValue.Bytes()), Data: member.data})
		default:
			return ExportArchive{}, fmt.Errorf("%w: unknown entry kind %q", ErrExportIntegrity, member.entry.Kind)
		}
	}
	archive.Current.Certificates = certificateGroups[0]
	archive.Lineage = finalizeExportPositions(positions["lineage"], lineageCertificateGroups)
	archive.RecoveryPoints = finalizeExportPositions(positions["recovery"], recoveryCertificateGroups)
	if len(archive.Current.Policy) == 0 || len(archive.Current.Control) == 0 || len(archive.Current.Certificates) == 0 || len(archive.Checkpoint) == 0 {
		return ExportArchive{}, ErrIncompleteExport
	}
	canonical, err := exportMembers(archive)
	if err != nil {
		return ExportArchive{}, err
	}
	canonicalManifest := manifestForArchive(archive, canonical)
	if !sameExportEntries(canonicalManifest.Entries, manifest.Entries) {
		return ExportArchive{}, fmt.Errorf("%w: noncanonical inventory", ErrExportIntegrity)
	}
	return archive, nil
}

func validateManifestMetadata(manifest ExportManifest) error {
	if manifest.FormatVersion != ExportFormatVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedExportVersion, manifest.FormatVersion)
	}
	for _, field := range []struct {
		value  string
		length int
	}{
		{manifest.VaultID, 32}, {manifest.AnchorFingerprint, 32}, {manifest.PolicyDigest, 32},
	} {
		decoded, err := hex.DecodeString(field.value)
		if err != nil || len(decoded) != field.length || strings.ToLower(field.value) != field.value {
			return fmt.Errorf("%w: malformed identity digest", ErrExportIntegrity)
		}
	}
	if len(manifest.Omissions) > maxExportOmissions {
		return fmt.Errorf("%w: omission count", ErrLimit)
	}
	seenOmissions := make(map[ExportOmissionCode]bool, len(manifest.Omissions))
	for _, omission := range manifest.Omissions {
		switch omission {
		case ExportOmissionUnavailableLocalHistory, ExportOmissionUnretainedRecovery, ExportOmissionUnavailableLocalBlobs:
		default:
			return fmt.Errorf("%w: invalid omission code", ErrExportIntegrity)
		}
		if seenOmissions[omission] {
			return fmt.Errorf("%w: duplicate omission code", ErrExportIntegrity)
		}
		seenOmissions[omission] = true
	}
	if !sameStrings(manifest.Limitations, []string{exportLimitationNeverHeld, exportLimitationScope, exportLimitationCAR}) {
		return fmt.Errorf("%w: required archive limitations are absent", ErrIncompleteExport)
	}
	return nil
}

func encodeExportManifest(manifest ExportManifest) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	encoded := buffer.Bytes()
	return bytes.Clone(encoded[:len(encoded)-1]), nil
}

func decodeExportManifest(data []byte) (ExportManifest, error) {
	if err := probeExportManifestVersion(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return ExportManifest{}, err
	}
	var manifest ExportManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ExportManifest{}, fmt.Errorf("%w: invalid manifest fields", ErrIncompleteExport)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ExportManifest{}, fmt.Errorf("%w: trailing manifest data", ErrExportIntegrity)
	}
	canonical, err := encodeExportManifest(manifest)
	if err != nil || !bytes.Equal(canonical, data) {
		return ExportManifest{}, fmt.Errorf("%w: manifest is not canonical JSON", ErrExportIntegrity)
	}
	if err := validateManifestMetadata(manifest); err != nil {
		return ExportManifest{}, err
	}
	return manifest, nil
}

func manifestHeaderSize(manifest ExportManifest) int64 {
	encoded, err := encodeExportManifest(manifest)
	if err != nil {
		return 0
	}
	return int64(len(encoded))
}

func ensureExportPosition(groups map[uint32]*ExportPosition, group uint32) *ExportPosition {
	if group == 0 {
		return nil
	}
	position := groups[group]
	if position == nil {
		position = &ExportPosition{}
		groups[group] = position
	}
	return position
}

func finalizeExportPositions(groups map[uint32]*ExportPosition, certificates map[uint32][][]byte) []ExportPosition {
	keys := make([]int, 0, len(groups))
	for group := range groups {
		keys = append(keys, int(group))
	}
	sort.Ints(keys)
	result := make([]ExportPosition, 0, len(keys))
	for _, key := range keys {
		position := *groups[uint32(key)]
		position.Certificates = certificates[uint32(key)]
		result = append(result, position)
	}
	return result
}

func sortedCertificates(certificates [][]byte) [][]byte {
	result := cloneByteSlices(certificates)
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i], result[j]) < 0 })
	return result
}

func sortedExportPositions(positions []ExportPosition) []ExportPosition {
	result := cloneExportPositions(positions)
	sort.Slice(result, func(i, j int) bool {
		left, _ := rawCID(result[i].Control)
		right, _ := rawCID(result[j].Control)
		return bytes.Compare(left, right) < 0
	})
	return result
}

func cloneExportPosition(position ExportPosition) ExportPosition {
	return ExportPosition{Policy: bytes.Clone(position.Policy), Control: bytes.Clone(position.Control), Certificates: cloneByteSlices(position.Certificates), Head: bytes.Clone(position.Head)}
}

func cloneExportPositions(positions []ExportPosition) []ExportPosition {
	result := make([]ExportPosition, len(positions))
	for index := range positions {
		result[index] = cloneExportPosition(positions[index])
	}
	return result
}

func sameExportEntries(left, right []ExportEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func tarMemberSize(size int64) int64 {
	return 512 + size + blockPadding(size)
}

func exportDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func mustRawCID(data []byte) []byte {
	encoded, _ := rawCID(data)
	return encoded
}
