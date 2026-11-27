package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var (
	errPublicationStoreUnsafe = errors.New(
		"the publication position store is not a private 0700 directory owned by the current user",
	)
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
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
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

func writeRebuildRequiredHint(command *urfave.Command, err error, directory string) {
	if !publicationstate.IsRebuildRequired(err) {
		return
	}
	writer := command.Root().ErrWriter
	fmt.Fprintln(
		writer,
		"dottie: the local publication state was written by an older build and is not upgraded in place",
	)
	fmt.Fprintf(writer, "dottie: local state: %s\n", escapeField(directory))
	fmt.Fprintln(writer, "dottie: it was left unchanged by this run")
	fmt.Fprintln(
		writer,
		"dottie: keep it until you no longer need it: journal.db and its apply backups may hold the only copies of the preimage for an interrupted apply",
	)
	rows, rowsErr := publicationstate.LiveJournalRows(directory)
	if rowsErr == nil && rows > 0 {
		fmt.Fprintln(writer, "dottie: live apply journal rows are recorded there")
		fmt.Fprintln(
			writer,
			"dottie: resolve them with a build that wrote them, or keep the directory as evidence; nothing here deletes it",
		)
	}
	fmt.Fprintln(
		writer,
		"dottie: a rebuild means a fresh state directory, not an in-place change; move the old one aside yourself when you have kept what you need",
	)
}
