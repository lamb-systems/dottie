package publicationstate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPublicationReadAcceptedMaterialRefusesReplacedPayloadDirectory(t *testing.T) {
	ctx := context.Background()
	fixture := newAcceptedMaterialDirectoryLinkCase(t)
	require.Equal(t, fixture.rootFD, fixture.store.rootFD)
	require.Equal(t, fixture.payloadFD, fixture.store.payloadFD)

	const heldName = "payloads-held"
	const sentinelName = "replacement.sentinel"
	sentinelBytes := []byte("replacement sentinel")
	requireNoEntryAt(t, fixture.store.rootFD, heldName)
	require.NoError(t, unix.Renameat(fixture.store.rootFD, payloadDirectoryName, fixture.store.rootFD, heldName))
	require.NoError(t, unix.Mkdirat(fixture.store.rootFD, payloadDirectoryName, 0o700))
	require.NoError(t, installAcceptedMaterialReplacementDirectory(fixture, sentinelName, sentinelBytes))

	before, err := observeAcceptedMaterialReplacedDirectory(fixture, heldName, sentinelName, len(sentinelBytes))
	require.NoError(t, err)
	require.Equal(t, fixture.rootIdentity, mustAcceptedMaterialDirectoryIdentity(t, fixture.store.rootFD))
	require.Equal(t, fixture.payloadDirectoryIdentity, before.HeldDescriptor)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.HeldName)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.HeldNameFD)
	require.Equal(t, fixture.healthyPayload, before.HeldPayload)
	require.Equal(t, fixture.healthyPayload, before.HeldNamePayload)
	require.Equal(t, acceptedMaterialDirectoryIdentity{Device: before.NamedPath.Device, Inode: before.NamedPath.Inode, UID: before.NamedPath.UID, Mode: before.NamedPath.Mode}, before.NamedFD)
	requireAcceptedMaterialPrivateDirectory(t, before.HeldDescriptor)
	requireAcceptedMaterialPrivateDirectory(t, before.HeldName)
	requireAcceptedMaterialPrivateDirectory(t, before.NamedPath)
	requireAcceptedMaterialPrivateDirectory(t, before.NamedFD)
	require.NotEqual(t, acceptedMaterialDirectoryPair{Device: before.HeldDescriptor.Device, Inode: before.HeldDescriptor.Inode}, acceptedMaterialDirectoryPair{Device: before.NamedPath.Device, Inode: before.NamedPath.Inode})
	requireAcceptedMaterialPayloadFile(t, before.HeldPayload, fixture.payload)
	requireAcceptedMaterialPayloadFile(t, before.HeldNamePayload, fixture.payload)
	requireAcceptedMaterialPayloadFile(t, before.NamedPayload, fixture.payload)
	require.Equal(t, acceptedMaterialFileState{}, before.HeldSentinel)
	requireAcceptedMaterialRegularFile(t, before.ReplacementSentinel, sentinelBytes, 0o600, 1)

	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.fixture.binding, fixture.expectedFloor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonIO)
	afterMaterial, err := observeAcceptedMaterialReplacedDirectory(fixture, heldName, sentinelName, len(sentinelBytes))
	require.NoError(t, err)
	assert.Equal(t, before, afterMaterial)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)

	candidate, err := fixture.store.ReadCandidate(ctx, fixture.attemptID)
	assert.Equal(t, CandidateMaterial{}, candidate)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonIO)
	afterCandidate, err := observeAcceptedMaterialReplacedDirectory(fixture, heldName, sentinelName, len(sentinelBytes))
	require.NoError(t, err)
	assert.Equal(t, before, afterCandidate)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)
}

func TestPublicationReadAcceptedMaterialRefusesPayloadSymlink(t *testing.T) {
	ctx := context.Background()
	fixture := newAcceptedMaterialDirectoryLinkCase(t)
	require.Equal(t, fixture.rootFD, fixture.store.rootFD)
	require.Equal(t, fixture.payloadFD, fixture.store.payloadFD)

	const heldName = "payload-held"
	requireNoEntryAt(t, fixture.store.payloadFD, heldName)
	require.NoError(t, unix.Renameat(fixture.store.payloadFD, fixture.basename, fixture.store.payloadFD, heldName))
	require.NoError(t, unix.Symlinkat(heldName, fixture.store.payloadFD, fixture.basename))

	before, err := observeAcceptedMaterialSymlink(fixture, heldName)
	require.NoError(t, err)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.Directory.HeldDescriptor)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.Directory.NamedPath)
	requireAcceptedMaterialPrivateDirectory(t, before.Directory.HeldDescriptor)
	require.Equal(t, fixture.healthyPayload.Device, before.HeldPayload.Device)
	require.Equal(t, fixture.healthyPayload.Inode, before.HeldPayload.Inode)
	require.Equal(t, uint32(unix.S_IFLNK), before.Link.Mode&uint32(unix.S_IFMT))
	require.Equal(t, heldName, before.Link.Target)
	require.Equal(t, int64(len(heldName)), before.Link.Size)
	require.Equal(t, uint32(os.Geteuid()), before.Link.UID)
	requireAcceptedMaterialPayloadFile(t, before.HeldPayload, fixture.payload)

	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.fixture.binding, fixture.expectedFloor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialUnsafe)
	afterMaterial, err := observeAcceptedMaterialSymlink(fixture, heldName)
	require.NoError(t, err)
	assert.Equal(t, before, afterMaterial)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)

	candidate, err := fixture.store.ReadCandidate(ctx, fixture.attemptID)
	assert.Equal(t, CandidateMaterial{}, candidate)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateUnsafe)
	afterCandidate, err := observeAcceptedMaterialSymlink(fixture, heldName)
	require.NoError(t, err)
	assert.Equal(t, before, afterCandidate)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)
}

func TestPublicationReadAcceptedMaterialRefusesPayloadHardLink(t *testing.T) {
	ctx := context.Background()
	fixture := newAcceptedMaterialDirectoryLinkCase(t)
	require.Equal(t, fixture.rootFD, fixture.store.rootFD)
	require.Equal(t, fixture.payloadFD, fixture.store.payloadFD)

	const aliasName = "payload.alias"
	requireNoEntryAt(t, fixture.store.payloadFD, aliasName)
	require.NoError(t, unix.Linkat(fixture.store.payloadFD, fixture.basename, fixture.store.payloadFD, aliasName, 0))

	before, err := observeAcceptedMaterialHardLink(fixture, aliasName)
	require.NoError(t, err)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.Directory.HeldDescriptor)
	require.Equal(t, fixture.payloadDirectoryIdentity, before.Directory.NamedPath)
	requireAcceptedMaterialPrivateDirectory(t, before.Directory.HeldDescriptor)
	require.Equal(t, fixture.healthyPayload.Device, before.Canonical.Device)
	require.Equal(t, fixture.healthyPayload.Inode, before.Canonical.Inode)
	requireAcceptedMaterialRegularFile(t, before.Canonical, fixture.payload, 0o600, 2)
	requireAcceptedMaterialRegularFile(t, before.Alias, fixture.payload, 0o600, 2)
	require.Equal(t, acceptedMaterialDirectoryPair{Device: before.Canonical.Device, Inode: before.Canonical.Inode}, acceptedMaterialDirectoryPair{Device: before.Alias.Device, Inode: before.Alias.Inode})

	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.fixture.binding, fixture.expectedFloor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialUnsafe)
	afterMaterial, err := observeAcceptedMaterialHardLink(fixture, aliasName)
	require.NoError(t, err)
	assert.Equal(t, before, afterMaterial)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)

	candidate, err := fixture.store.ReadCandidate(ctx, fixture.attemptID)
	assert.Equal(t, CandidateMaterial{}, candidate)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateUnsafe)
	afterCandidate, err := observeAcceptedMaterialHardLink(fixture, aliasName)
	require.NoError(t, err)
	assert.Equal(t, before, afterCandidate)
	assertAcceptedMaterialDirectoryLinkPublicState(t, fixture)
}

type acceptedMaterialDirectoryLinkCase struct {
	fixture                  fixture
	store                    *Store
	directory                string
	attemptID                [16]byte
	candidate                CandidateInput
	expectedFloor            Floor
	record                   []byte
	payload                  []byte
	basename                 string
	rootFD                   int
	payloadFD                int
	rootIdentity             acceptedMaterialDirectoryIdentity
	payloadDirectoryIdentity acceptedMaterialDirectoryIdentity
	publicState              acceptedMaterialCustodyState
	logicalRows              map[string]string
	healthyPayload           acceptedMaterialFileState
}

func newAcceptedMaterialDirectoryLinkCase(t *testing.T) *acceptedMaterialDirectoryLinkCase {
	t.Helper()
	fixture := newFixture(t, BackendPublicRepo)
	fixture.appendRecord(t, 0)
	require.NotEmpty(t, fixture.payload)
	require.GreaterOrEqual(t, len(fixture.payload), 2)

	candidate := attemptCandidate(fixture, 0)
	require.NotEmpty(t, candidate.Payload)
	require.GreaterOrEqual(t, len(candidate.Payload), 2)
	require.LessOrEqual(t, uint64(len(candidate.Payload)), publication.MaxBlobBytes)
	store, directory := newStore(t, fixture)
	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})
	attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, fixture, candidate)
	expectedFloor := cloneFloor(finalized.Floor)
	record := bytes.Clone(candidate.SnapshotRecord)
	payload := bytes.Clone(candidate.Payload)
	basename, err := payloadBasenameFromCID(expectedFloor.BlobCID)
	require.NoError(t, err)
	require.True(t, validPayloadBasename(basename))
	require.Equal(t, payloadBasename(payload), basename)
	require.Equal(t, uint64(len(payload)), expectedFloor.BlobSize)

	material, err := store.ReadAcceptedMaterial(context.Background(), fixture.binding, expectedFloor)
	require.NoError(t, err)
	require.Equal(t, expectedFloor, material.Floor)
	require.Equal(t, record, material.SnapshotRecord)
	require.Equal(t, payload, material.Payload)
	publicState := readAcceptedMaterialCustodyState(t, store, attempt.ID, candidate)
	require.Equal(t, expectedFloor, publicState.Floor)
	require.Equal(t, record, publicState.Candidate.SnapshotRecord)
	require.Equal(t, payload, publicState.Candidate.Payload)
	logicalRows := readAttemptLogicalRows(t, store)

	require.GreaterOrEqual(t, store.rootFD, 0)
	require.GreaterOrEqual(t, store.payloadFD, 0)
	rootIdentity, err := acceptedMaterialDirectoryIdentityFromFD(store.rootFD)
	require.NoError(t, err)
	requireAcceptedMaterialPrivateDirectory(t, rootIdentity)
	payloadDirectoryIdentity, err := acceptedMaterialDirectoryIdentityFromFD(store.payloadFD)
	require.NoError(t, err)
	requireAcceptedMaterialPrivateDirectory(t, payloadDirectoryIdentity)
	namedDirectoryIdentity, err := acceptedMaterialDirectoryIdentityAt(store.rootFD, payloadDirectoryName)
	require.NoError(t, err)
	requireAcceptedMaterialPrivateDirectory(t, namedDirectoryIdentity)
	require.Equal(t, payloadDirectoryIdentity, namedDirectoryIdentity)
	physicalPayload, err := observeAcceptedMaterialRegularAt(store.payloadFD, basename, len(payload))
	require.NoError(t, err)
	requireAcceptedMaterialPayloadFile(t, physicalPayload, payload)

	return &acceptedMaterialDirectoryLinkCase{
		fixture: fixture, store: store, directory: directory, attemptID: attempt.ID, candidate: candidate,
		expectedFloor: expectedFloor, record: record, payload: payload, basename: basename,
		rootFD: store.rootFD, payloadFD: store.payloadFD, rootIdentity: rootIdentity,
		payloadDirectoryIdentity: payloadDirectoryIdentity, publicState: publicState, logicalRows: logicalRows,
		healthyPayload: physicalPayload,
	}
}

func assertAcceptedMaterialDirectoryLinkPublicState(t *testing.T, fixture *acceptedMaterialDirectoryLinkCase) {
	t.Helper()
	assert.Equal(t, fixture.rootFD, fixture.store.rootFD)
	assert.Equal(t, fixture.payloadFD, fixture.store.payloadFD)
	rootIdentity, err := acceptedMaterialDirectoryIdentityFromFD(fixture.store.rootFD)
	require.NoError(t, err)
	assert.Equal(t, fixture.rootIdentity, rootIdentity)
	payloadIdentity, err := acceptedMaterialDirectoryIdentityFromFD(fixture.store.payloadFD)
	require.NoError(t, err)
	assert.Equal(t, fixture.payloadDirectoryIdentity, payloadIdentity)
	assertAcceptedMaterialCustodyPublicState(t, fixture.store, fixture.attemptID, fixture.publicState)
	assert.Equal(t, fixture.logicalRows, readAttemptLogicalRows(t, fixture.store))
	assert.Equal(t, fixture.expectedFloor, fixture.publicState.Floor)
	assert.Equal(t, fixture.record, fixture.candidate.SnapshotRecord)
	assert.Equal(t, fixture.payload, fixture.candidate.Payload)
}

type acceptedMaterialDirectoryIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	Mode   uint32
}

type acceptedMaterialDirectoryPair struct {
	Device uint64
	Inode  uint64
}

type acceptedMaterialFileState struct {
	Exists bool
	Device uint64
	Inode  uint64
	UID    uint32
	Nlink  uint64
	Mode   uint32
	Size   int64
	Bytes  []byte
}

type acceptedMaterialSymlinkState struct {
	Device uint64
	Inode  uint64
	UID    uint32
	Nlink  uint64
	Mode   uint32
	Size   int64
	Target string
}

type acceptedMaterialDirectoryPairState struct {
	HeldDescriptor acceptedMaterialDirectoryIdentity
	NamedPath      acceptedMaterialDirectoryIdentity
}

type acceptedMaterialReplacedDirectoryState struct {
	HeldDescriptor      acceptedMaterialDirectoryIdentity
	HeldName            acceptedMaterialDirectoryIdentity
	HeldNameFD          acceptedMaterialDirectoryIdentity
	NamedPath           acceptedMaterialDirectoryIdentity
	NamedFD             acceptedMaterialDirectoryIdentity
	HeldPayload         acceptedMaterialFileState
	HeldNamePayload     acceptedMaterialFileState
	NamedPayload        acceptedMaterialFileState
	HeldSentinel        acceptedMaterialFileState
	ReplacementSentinel acceptedMaterialFileState
}

type acceptedMaterialSymlinkNamespaceState struct {
	Directory   acceptedMaterialDirectoryPairState
	Link        acceptedMaterialSymlinkState
	HeldPayload acceptedMaterialFileState
}

type acceptedMaterialHardLinkNamespaceState struct {
	Directory acceptedMaterialDirectoryPairState
	Canonical acceptedMaterialFileState
	Alias     acceptedMaterialFileState
}

func installAcceptedMaterialReplacementDirectory(fixture *acceptedMaterialDirectoryLinkCase, sentinelName string, sentinelBytes []byte) (resultErr error) {
	directoryFD, err := unix.Openat(fixture.store.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := unix.Close(directoryFD)
		if resultErr == nil {
			resultErr = closeErr
		}
	}()
	if err := unix.Fchmod(directoryFD, 0o700); err != nil {
		return err
	}
	if err := createAcceptedMaterialRegularAt(directoryFD, fixture.basename, fixture.payload, 0o600); err != nil {
		return err
	}
	if err := createAcceptedMaterialRegularAt(directoryFD, sentinelName, sentinelBytes, 0o600); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func createAcceptedMaterialRegularAt(directoryFD int, name string, data []byte, mode uint32) (resultErr error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := unix.Close(fd)
		if resultErr == nil {
			resultErr = closeErr
		}
	}()
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	if err := writeAcceptedMaterialFixtureBytes(fd, data); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func writeAcceptedMaterialFixtureBytes(fd int, data []byte) error {
	for offset := 0; offset < len(data); {
		count, err := unix.Write(fd, data[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		offset += count
	}
	return nil
}

func observeAcceptedMaterialReplacedDirectory(fixture *acceptedMaterialDirectoryLinkCase, heldName, sentinelName string, sentinelLength int) (state acceptedMaterialReplacedDirectoryState, resultErr error) {
	state.HeldDescriptor, resultErr = acceptedMaterialDirectoryIdentityFromFD(fixture.store.payloadFD)
	if resultErr != nil {
		return state, resultErr
	}
	state.HeldName, resultErr = acceptedMaterialDirectoryIdentityAt(fixture.store.rootFD, heldName)
	if resultErr != nil {
		return state, resultErr
	}
	state.NamedPath, resultErr = acceptedMaterialDirectoryIdentityAt(fixture.store.rootFD, payloadDirectoryName)
	if resultErr != nil {
		return state, resultErr
	}
	heldNameFD, err := unix.Openat(fixture.store.rootFD, heldName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return state, err
	}
	defer func() {
		closeErr := unix.Close(heldNameFD)
		if resultErr == nil {
			resultErr = closeErr
		}
	}()
	state.HeldNameFD, resultErr = acceptedMaterialDirectoryIdentityFromFD(heldNameFD)
	if resultErr != nil {
		return state, resultErr
	}
	namedFD, err := unix.Openat(fixture.store.rootFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return state, err
	}
	defer func() {
		closeErr := unix.Close(namedFD)
		if resultErr == nil {
			resultErr = closeErr
		}
	}()
	state.NamedFD, resultErr = acceptedMaterialDirectoryIdentityFromFD(namedFD)
	if resultErr != nil {
		return state, resultErr
	}
	state.HeldPayload, resultErr = observeAcceptedMaterialRegularAt(fixture.store.payloadFD, fixture.basename, len(fixture.payload))
	if resultErr != nil {
		return state, resultErr
	}
	state.HeldNamePayload, resultErr = observeAcceptedMaterialRegularAt(heldNameFD, fixture.basename, len(fixture.payload))
	if resultErr != nil {
		return state, resultErr
	}
	state.NamedPayload, resultErr = observeAcceptedMaterialRegularAt(namedFD, fixture.basename, len(fixture.payload))
	if resultErr != nil {
		return state, resultErr
	}
	state.HeldSentinel, resultErr = observeAcceptedMaterialRegularAt(heldNameFD, sentinelName, sentinelLength)
	if resultErr != nil {
		return state, resultErr
	}
	state.ReplacementSentinel, resultErr = observeAcceptedMaterialRegularAt(namedFD, sentinelName, sentinelLength)
	if resultErr != nil {
		return state, resultErr
	}
	return state, nil
}

func observeAcceptedMaterialSymlink(fixture *acceptedMaterialDirectoryLinkCase, heldName string) (state acceptedMaterialSymlinkNamespaceState, resultErr error) {
	state.Directory, resultErr = observeAcceptedMaterialDirectoryPair(fixture)
	if resultErr != nil {
		return state, resultErr
	}
	state.Link, resultErr = observeAcceptedMaterialSymlinkAt(fixture.store.payloadFD, fixture.basename, len(heldName))
	if resultErr != nil {
		return state, resultErr
	}
	state.HeldPayload, resultErr = observeAcceptedMaterialRegularAt(fixture.store.payloadFD, heldName, len(fixture.payload))
	return state, resultErr
}

func observeAcceptedMaterialHardLink(fixture *acceptedMaterialDirectoryLinkCase, aliasName string) (state acceptedMaterialHardLinkNamespaceState, resultErr error) {
	state.Directory, resultErr = observeAcceptedMaterialDirectoryPair(fixture)
	if resultErr != nil {
		return state, resultErr
	}
	state.Canonical, resultErr = observeAcceptedMaterialRegularAt(fixture.store.payloadFD, fixture.basename, len(fixture.payload))
	if resultErr != nil {
		return state, resultErr
	}
	state.Alias, resultErr = observeAcceptedMaterialRegularAt(fixture.store.payloadFD, aliasName, len(fixture.payload))
	return state, resultErr
}

func observeAcceptedMaterialDirectoryPair(fixture *acceptedMaterialDirectoryLinkCase) (acceptedMaterialDirectoryPairState, error) {
	held, err := acceptedMaterialDirectoryIdentityFromFD(fixture.store.payloadFD)
	if err != nil {
		return acceptedMaterialDirectoryPairState{}, err
	}
	named, err := acceptedMaterialDirectoryIdentityAt(fixture.store.rootFD, payloadDirectoryName)
	if err != nil {
		return acceptedMaterialDirectoryPairState{}, err
	}
	return acceptedMaterialDirectoryPairState{HeldDescriptor: held, NamedPath: named}, nil
}

func acceptedMaterialDirectoryIdentityAt(directoryFD int, name string) (acceptedMaterialDirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return acceptedMaterialDirectoryIdentity{}, err
	}
	return acceptedMaterialDirectoryIdentityFromStat(&stat), nil
}

func acceptedMaterialDirectoryIdentityFromFD(fd int) (acceptedMaterialDirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return acceptedMaterialDirectoryIdentity{}, err
	}
	return acceptedMaterialDirectoryIdentityFromStat(&stat), nil
}

func acceptedMaterialDirectoryIdentityFromStat(stat *unix.Stat_t) acceptedMaterialDirectoryIdentity {
	return acceptedMaterialDirectoryIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, Mode: stat.Mode}
}

func mustAcceptedMaterialDirectoryIdentity(t *testing.T, fd int) acceptedMaterialDirectoryIdentity {
	t.Helper()
	identity, err := acceptedMaterialDirectoryIdentityFromFD(fd)
	require.NoError(t, err)
	return identity
}

func observeAcceptedMaterialRegularAt(directoryFD int, name string, maximumBytes int) (state acceptedMaterialFileState, resultErr error) {
	if maximumBytes < 0 || uint64(maximumBytes) > publication.MaxBlobBytes {
		return acceptedMaterialFileState{}, errors.New("invalid fixture read bound")
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return acceptedMaterialFileState{}, nil
	}
	if err != nil {
		return acceptedMaterialFileState{}, err
	}
	defer func() {
		closeErr := unix.Close(fd)
		if resultErr == nil {
			resultErr = closeErr
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return state, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > int64(maximumBytes+1) {
		return state, errors.New("unexpected fixture file metadata")
	}
	buffer := make([]byte, maximumBytes+1)
	offset := 0
	for offset < len(buffer) {
		count, readErr := unix.Pread(fd, buffer[offset:], int64(offset))
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return state, readErr
		}
		if count == 0 {
			break
		}
		offset += count
	}
	if int64(offset) != stat.Size {
		return state, errors.New("fixture file changed while observed")
	}
	state = acceptedMaterialFileState{
		Exists: true, Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid,
		Nlink: uint64(stat.Nlink), Mode: stat.Mode, Size: stat.Size, Bytes: bytes.Clone(buffer[:offset]),
	}
	return state, nil
}

func observeAcceptedMaterialSymlinkAt(directoryFD int, name string, maximumTargetBytes int) (acceptedMaterialSymlinkState, error) {
	if maximumTargetBytes < 0 || maximumTargetBytes > 4096 {
		return acceptedMaterialSymlinkState{}, errors.New("invalid fixture link bound")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return acceptedMaterialSymlinkState{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK || stat.Size < 0 || stat.Size > int64(maximumTargetBytes) {
		return acceptedMaterialSymlinkState{}, errors.New("unexpected fixture link metadata")
	}
	buffer := make([]byte, maximumTargetBytes+1)
	count, err := unix.Readlinkat(directoryFD, name, buffer)
	if err != nil {
		return acceptedMaterialSymlinkState{}, err
	}
	if count > maximumTargetBytes || int64(count) != stat.Size {
		return acceptedMaterialSymlinkState{}, errors.New("fixture link changed while observed")
	}
	return acceptedMaterialSymlinkState{
		Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, Nlink: uint64(stat.Nlink),
		Mode: stat.Mode, Size: stat.Size, Target: string(buffer[:count]),
	}, nil
}

func requireNoEntryAt(t *testing.T, directoryFD int, name string) {
	t.Helper()
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	require.ErrorIs(t, err, unix.ENOENT)
}

func requireAcceptedMaterialPrivateDirectory(t *testing.T, state acceptedMaterialDirectoryIdentity) {
	t.Helper()
	require.Equal(t, uint32(os.Geteuid()), state.UID)
	require.Equal(t, uint32(unix.S_IFDIR|0o700), state.Mode&uint32(unix.S_IFMT|0o777))
	require.Zero(t, state.Mode&0o7000)
}

func requireAcceptedMaterialPayloadFile(t *testing.T, state acceptedMaterialFileState, payload []byte) {
	t.Helper()
	requireAcceptedMaterialRegularFile(t, state, payload, 0o600, 1)
}

func requireAcceptedMaterialRegularFile(t *testing.T, state acceptedMaterialFileState, expected []byte, permissions uint32, nlink uint64) {
	t.Helper()
	require.True(t, state.Exists)
	require.Equal(t, uint32(os.Geteuid()), state.UID)
	require.Equal(t, uint32(unix.S_IFREG)|permissions, state.Mode&uint32(unix.S_IFMT|0o777))
	require.Zero(t, state.Mode&0o7000)
	require.Equal(t, nlink, state.Nlink)
	require.Equal(t, int64(len(expected)), state.Size)
	require.Equal(t, expected, state.Bytes)
}
