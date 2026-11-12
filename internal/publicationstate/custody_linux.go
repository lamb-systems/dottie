//go:build linux

package publicationstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/multiformats/go-multihash"
)

const payloadDirectoryName = "payloads"
const payloadSuffix = ".payload"

var errUnsafePayloadObject = errors.New("unsafe payload object")
var errCorruptPayloadObject = errors.New("corrupt payload object")
var errInvalidPayloadInput = errors.New("invalid payload input")

type custodyOperations struct {
	openTemp func(int, uint32) (int, error)
	write    func(int, []byte) (int, error)
	sync     func(int) error
	link     func(int, int, string) error
}

func defaultCustodyOperations() custodyOperations {
	return custodyOperations{
		openTemp: func(directoryFD int, mode uint32) (int, error) {
			return unix.Openat(directoryFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, mode)
		},
		write: unix.Write,
		sync:  unix.Fsync,
		link: func(fd, directoryFD int, name string) error {
			return unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", fd), directoryFD, name, unix.AT_SYMLINK_FOLLOW)
		},
	}
}

func openStoreRoot(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 || stat.Mode&0o7000 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("unsafe root")
	}
	return fd, nil
}

func (s *Store) openPayloadDirectoryForRead() error {
	if s.payloadFD >= 0 {
		return s.validatePinnedPayloadDirectory()
	}
	fd, err := unix.Openat(s.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 || stat.Mode&0o7000 != 0 {
		_ = unix.Close(fd)
		return errors.New("unsafe payload directory")
	}
	s.payloadFD = fd
	return nil
}

func (s *Store) ensurePayloadDirectory() error {
	if s.payloadFD >= 0 {
		return s.validatePinnedPayloadDirectory()
	}
	created := false
	if err := unix.Mkdirat(s.rootFD, payloadDirectoryName, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(s.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7000 != 0 {
		_ = unix.Close(fd)
		return errors.New("unsafe payload directory")
	}
	if created {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			_ = unix.Close(fd)
			return err
		}
	} else if stat.Mode&0o777 != 0o700 || stat.Mode&0o7000 != 0 {
		_ = unix.Close(fd)
		return errors.New("unsafe payload directory")
	}
	if err := s.syncCustodyFD(s.rootFD); err != nil {
		_ = unix.Close(fd)
		return err
	}
	s.payloadFD = fd
	return nil
}

func (s *Store) validatePinnedPayloadDirectory() error {
	var stat unix.Stat_t
	if err := unix.Fstat(s.payloadFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 || stat.Mode&0o7000 != 0 {
		return errors.New("unsafe payload directory")
	}
	var named unix.Stat_t
	if err := unix.Fstatat(s.rootFD, payloadDirectoryName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if named.Dev != stat.Dev || named.Ino != stat.Ino {
		return errors.New("changed payload directory")
	}
	return nil
}

func payloadBasename(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]) + payloadSuffix
}

func payloadBasenameFromCID(encoded []byte) (string, error) {
	identifier, err := cid.Cast(encoded)
	if err != nil {
		return "", err
	}
	prefix := identifier.Prefix()
	if prefix.Version != 1 || prefix.Codec != cid.Raw || prefix.MhType != multihash.SHA2_256 || prefix.MhLength != 32 {
		return "", errors.New("unsupported blob CID")
	}
	decoded, err := multihash.Decode(identifier.Hash())
	if err != nil || len(decoded.Digest) != 32 {
		return "", errors.New("invalid blob CID")
	}
	return hex.EncodeToString(decoded.Digest) + payloadSuffix, nil
}

func (s *Store) inspectPayloadFile(name string, expected []byte, blob publication.BlobReference) ([]byte, error) {
	if !validPayloadBasename(name) {
		return nil, errors.New("invalid payload name")
	}
	fd, err := unix.Openat(s.payloadFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	data, readErr := readValidatedPayloadFD(fd, blob)
	closeErr := unix.Close(fd)
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if expected != nil && !bytes.Equal(data, expected) {
		return nil, errors.New("payload mismatch")
	}
	return data, nil
}

func readValidatedPayloadFD(fd int, blob publication.BlobReference) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o600 || stat.Mode&0o7000 != 0 || stat.Nlink != 1 || stat.Size <= 0 || uint64(stat.Size) != blob.Size || blob.Size > publication.MaxBlobBytes {
		return nil, errUnsafePayloadObject
	}
	length := int(blob.Size)
	data := make([]byte, length+1)
	offset := 0
	for offset < len(data) {
		count, err := unix.Pread(fd, data[offset:], int64(offset))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if count == 0 {
			break
		}
		offset += count
	}
	if offset != length {
		return nil, io.ErrUnexpectedEOF
	}
	data = data[:length]
	if err := publication.VerifyPayload(data, blob); err != nil {
		return nil, errCorruptPayloadObject
	}
	if _, err := publication.DecodePayload(data, blob); err != nil {
		return nil, errCorruptPayloadObject
	}
	return data, nil
}

func (s *Store) writeAnonymousPayload(ctx context.Context, payload []byte, blob publication.BlobReference, name string) (result error) {
	fd, err := s.custodyOps.openTemp(s.payloadFD, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unix.Close(fd); result == nil && closeErr != nil {
			result = closeErr
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	for offset := 0; offset < len(payload); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := offset + 64*1024
		if end > len(payload) {
			end = len(payload)
		}
		written, err := s.custodyOps.write(fd, payload[offset:end])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		offset += written
	}
	if err := s.syncCustodyFD(fd); err != nil {
		return err
	}
	if err := s.custodyOps.link(fd, s.payloadFD, name); err != nil {
		return err
	}
	if err := s.syncCustodyFD(s.payloadFD); err != nil {
		return err
	}
	if err := s.syncCustodyFD(s.rootFD); err != nil {
		return err
	}
	if _, err := readValidatedPayloadFD(fd, blob); err != nil {
		return err
	}
	return nil
}

func validPayloadBasename(name string) bool {
	if !strings.HasSuffix(name, payloadSuffix) {
		return false
	}
	digest := strings.TrimSuffix(name, payloadSuffix)
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil && strings.ToLower(digest) == digest
}

func (s *Store) syncPayloadOwnership(name string, blob publication.BlobReference) (result []byte, resultErr error) {
	if !validPayloadBasename(name) {
		return nil, errors.New("invalid payload name")
	}
	fd, err := unix.Openat(s.payloadFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := unix.Close(fd); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	data, err := readValidatedPayloadFD(fd, blob)
	if err != nil {
		return nil, err
	}
	if err := s.syncCustodyFD(fd); err != nil {
		return nil, err
	}
	if err := s.syncCustodyFD(s.payloadFD); err != nil {
		return nil, err
	}
	if err := s.syncCustodyFD(s.rootFD); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Store) syncCustodyFD(fd int) error {
	if s.custodyOps.sync != nil {
		return s.custodyOps.sync(fd)
	}
	return unix.Fsync(fd)
}

func (s *Store) inventoryPayloads() (map[string]uint64, uint64, error) {
	if err := s.ensurePayloadDirectory(); err != nil {
		return nil, 0, err
	}
	dup, err := unix.Openat(s.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	var named, pinned unix.Stat_t
	if unix.Fstat(dup, &named) != nil || unix.Fstat(s.payloadFD, &pinned) != nil || named.Dev != pinned.Dev || named.Ino != pinned.Ino {
		_ = unix.Close(dup)
		return nil, 0, errors.New("changed payload directory")
	}
	file := os.NewFile(uintptr(dup), payloadDirectoryName)
	names, err := file.Readdirnames(int(s.attemptLimits.ManagedObjects) + 1)
	closeErr := file.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	if closeErr != nil {
		return nil, 0, closeErr
	}
	if uint32(len(names)) > s.attemptLimits.ManagedObjects {
		return nil, 0, errors.New("payload inventory capacity")
	}
	objects := make(map[string]uint64, len(names))
	var total uint64
	for _, name := range names {
		if !validPayloadBasename(name) {
			return nil, 0, errors.New("unknown payload object")
		}
		fd, err := unix.Openat(s.payloadFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, 0, err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o600 || stat.Mode&0o7000 != 0 || stat.Nlink != 1 || stat.Size <= 0 || uint64(stat.Size) > publication.MaxBlobBytes {
			return nil, 0, errors.New("unsafe payload object")
		}
		size := uint64(stat.Size)
		objects[name] = size
		if ^uint64(0)-total < size {
			return nil, 0, errors.New("payload inventory overflow")
		}
		total += size
	}
	return objects, total, nil
}

func (s *Store) checkPayloadCapacity(ctx context.Context, name string, size uint64, createDirectory bool) error {
	return s.checkPayloadCapacityWithQueryer(ctx, s.conn, name, size, createDirectory)
}

func (s *Store) checkPayloadCapacityWithQueryer(ctx context.Context, q queryer, name string, size uint64, createDirectory bool) error {
	if s.payloadFD < 0 && !createDirectory {
		fd, openErr := unix.Openat(s.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if errors.Is(openErr, unix.ENOENT) {
			var catalogued any
			if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&catalogued); err != nil {
				return err
			}
			count, ok := rawInt64(catalogued)
			if !ok || count != 0 || size > s.attemptLimits.CustodyBytes || s.attemptLimits.ManagedObjects == 0 {
				return errors.New("payload inventory")
			}
			return nil
		}
		if openErr != nil {
			return openErr
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 || stat.Mode&0o7000 != 0 {
			_ = unix.Close(fd)
			return errors.New("unsafe payload directory")
		}
		s.payloadFD = fd
	}
	objects, total, err := s.inventoryPayloads()
	if err != nil {
		return err
	}
	registered := map[string]uint64{}
	rows, err := q.QueryContext(ctx, "SELECT blob_cid,basename,size FROM payload_objects")
	if err != nil {
		return err
	}
	for rows.Next() {
		var cidValue any
		var basename string
		var stored any
		if err := rows.Scan(&cidValue, &basename, &stored); err != nil {
			_ = rows.Close()
			return err
		}
		blobCID, cidOK := rawBytes(cidValue)
		storedSize, ok := rawInt64(stored)
		wantedName, nameErr := payloadBasenameFromCID(blobCID)
		if !cidOK || !ok || storedSize <= 0 || !validPayloadBasename(basename) || nameErr != nil || wantedName != basename {
			_ = rows.Close()
			return errStoredValue
		}
		registered[basename] = uint64(storedSize)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for basename, cataloguedSize := range registered {
		actualSize, exists := objects[basename]
		if !exists {
			if ^uint64(0)-total < cataloguedSize {
				return errors.New("payload inventory overflow")
			}
			total += cataloguedSize
			objects[basename] = cataloguedSize
		} else if actualSize != cataloguedSize {
			return errStoredValue
		}
	}
	if uint32(len(objects)) > s.attemptLimits.ManagedObjects || total > s.attemptLimits.CustodyBytes {
		return errors.New("payload capacity")
	}
	if existingSize, exists := objects[name]; exists {
		if existingSize != size {
			return errStoredValue
		}
		return nil
	}
	if uint32(len(objects)) >= s.attemptLimits.ManagedObjects || size > s.attemptLimits.CustodyBytes || total > s.attemptLimits.CustodyBytes-size {
		return errors.New("payload capacity")
	}
	return nil
}

func validatePayloadForCustody(payload []byte, blob publication.BlobReference, name string) error {
	if len(payload) == 0 || uint64(len(payload)) > publication.MaxBlobBytes || blob.Size == 0 || blob.Size > publication.MaxBlobBytes || uint64(len(payload)) != blob.Size || len(blob.CID) == 0 || len(blob.CID) > publication.MaxCIDBytes || len(name) != 64+len(payloadSuffix) {
		return errInvalidPayloadInput
	}
	canonicalName, err := payloadBasenameFromCID(blob.CID)
	if err != nil || !validPayloadBasename(name) || name != canonicalName || payloadBasename(payload) != canonicalName {
		return errInvalidPayloadInput
	}
	if err := publication.VerifyPayload(payload, blob); err != nil {
		return errInvalidPayloadInput
	}
	if _, err := publication.DecodePayload(payload, blob); err != nil {
		return errInvalidPayloadInput
	}
	return nil
}

func (s *Store) persistCandidatePayload(ctx context.Context, candidate validatedCandidate) (string, []byte, error) {
	return s.persistPayload(ctx, s.conn, candidate.payload, attemptPayloadReference(candidate), payloadBasename(candidate.payload))
}

func (s *Store) persistPayload(ctx context.Context, q queryer, payload []byte, blob publication.BlobReference, name string) (string, []byte, error) {
	if err := validatePayloadForCustody(payload, blob, name); err != nil {
		return "", nil, err
	}
	if err := s.ensurePayloadDirectory(); err != nil {
		return "", nil, err
	}
	var cataloguedName string
	var cataloguedSize any
	err := q.QueryRowContext(ctx, "SELECT basename,size FROM payload_objects WHERE blob_cid=?", blob.CID).Scan(&cataloguedName, &cataloguedSize)
	if err == nil {
		size, ok := rawInt64(cataloguedSize)
		if !ok || size <= 0 || uint64(size) != blob.Size || cataloguedName != name {
			return "", nil, errStoredValue
		}
		if _, err := s.syncPayloadOwnership(name, blob); err != nil {
			return "", nil, err
		}
		return name, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}
	if err := s.checkPayloadCapacityWithQueryer(ctx, q, name, blob.Size, true); err != nil {
		return "", nil, err
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(s.payloadFD, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if _, err := s.syncPayloadOwnership(name, blob); err != nil {
			return "", nil, err
		}
		return name, nil, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return "", nil, err
	}
	if err := s.writeAnonymousPayload(ctx, payload, blob, name); err != nil {
		return "", nil, err
	}
	data, err := s.syncPayloadOwnership(name, blob)
	if err != nil {
		return "", nil, err
	}
	return name, data, nil
}
