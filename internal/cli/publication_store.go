package cli

import (
	"errors"
	"os"
	"syscall"

	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var (
	errPublicationStoreUnsafe   = errors.New("the publication position store is not a private 0700 directory owned by the current user")
	errPublicationStoreCreation = errors.New("the publication position store directory cannot be created")
)

func checkPublicationStoreDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errPublicationStoreUnsafe
	}
	return verifyPublicationStoreDirectory(info)
}

func provisionPublicationStoreDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errPublicationStoreCreation
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return errPublicationStoreCreation
		}
		info, err = os.Lstat(directory)
		if err != nil {
			return errPublicationStoreCreation
		}
	}
	if err != nil {
		return errPublicationStoreUnsafe
	}
	return verifyPublicationStoreDirectory(info)
}

func verifyPublicationStoreDirectory(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errPublicationStoreUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errPublicationStoreUnsafe
	}
	return nil
}

func openPublicationPositionStore(directory string, binding publicationstate.Binding) (*publicationstate.Store, error) {
	if err := provisionPublicationStoreDirectory(directory); err != nil {
		return nil, err
	}
	return publicationstate.Open(directory, binding)
}
