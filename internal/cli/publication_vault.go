package cli

import (
	"context"
	"errors"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
)

const (
	pullVaultFromBinding  = "binding"
	pullVaultFromProvider = "provider"
)

type pullVaultFactory func(context.Context, *urfave.Command, pushSession) ([32]byte, error)

type resolvedVault struct {
	Vault  [32]byte
	Origin string
}

func resolvePublicationVault(ctx context.Context, command *urfave.Command, label string, vaults pullVaultFactory, session pushSession, override [32]byte, directory string) (resolvedVault, error) {
	if override != ([32]byte{}) {
		return resolvedVault{Vault: override}, nil
	}
	stored, err := publicationstate.ReadBinding(directory)
	if err != nil && !publicationPositionAbsent(err) {
		return resolvedVault{}, unreadablePositionExit(command, label, pullStoreReason(err))
	}
	if stored.Vault != ([32]byte{}) {
		return resolvedVault{Vault: stored.Vault, Origin: pullVaultFromBinding}, nil
	}
	published, err := vaults(ctx, command, session)
	if err != nil {
		return resolvedVault{}, publishedVaultFailure(command, label, err)
	}
	return resolvedVault{Vault: published, Origin: pullVaultFromProvider}, nil
}

func publicationPositionAbsent(err error) bool {
	var storeError *publicationstate.Error
	return errors.As(err, &storeError) && storeError.Reason() == publicationstate.ReasonPositionAbsent
}

func renderResolvedVault(vault resolvedVault) string {
	switch vault.Origin {
	case pullVaultFromBinding:
		return fmt.Sprintf("vault: %x (resolved from the recorded binding)\n", vault.Vault)
	case pullVaultFromProvider:
		return fmt.Sprintf("vault: %x (adopted from the published position at self)\n", vault.Vault)
	}
	return ""
}

func writeResolvedVault(command *urfave.Command, vault resolvedVault) error {
	output := renderResolvedVault(vault)
	if output == "" {
		return nil
	}
	return writeCommandOutput(command, output)
}

func unreadablePositionExit(command *urfave.Command, label, reason string) error {
	if err := writeCommandOutput(command, renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: reason})); err != nil {
		return err
	}
	return urfave.Exit(label+" refused: the local position store cannot be inspected read-only; nothing was changed", 3)
}

func publishedVaultFailure(command *urfave.Command, label string, err error) error {
	if errors.Is(err, service.ErrPublicationHeadAbsent) {
		if writeErr := writeCommandOutput(command, renderPullFinding(pullFinding{Kind: pullFindingNoPublication})); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(label+" refused: the account publishes no v2 position record at self, so there is no vault to adopt; pass --vault to name the vault this command acts on; nothing was changed", 3)
	}
	finding := pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonHead}
	var reasoned pullViewReasoner
	if errors.As(err, &reasoned) {
		finding.Reason = reasoned.Reason()
	}
	if writeErr := writeCommandOutput(command, renderPullFinding(finding)); writeErr != nil {
		return writeErr
	}
	if errors.Is(err, atproto.ErrAmbiguousTransport) || errors.Is(err, atproto.ErrRevisionMoving) {
		return urfave.Exit(label+" is indeterminate: the published vault read did not resolve; re-run dottie "+label, 4)
	}
	if errors.Is(err, service.ErrPublicationHeadIdentity) || errors.Is(err, service.ErrPublicationHeadInput) {
		return urfave.Exit(label+" refused: the account identity does not match the authorized session; nothing was changed", 3)
	}
	return urfave.Exit(label+" refused: the published vault cannot be read or validated; nothing was changed", 3)
}

func productionPullVaultFactory(openKeyring accountKeyringFactory, env func(string) string) pullVaultFactory {
	return func(ctx context.Context, _ *urfave.Command, session pushSession) ([32]byte, error) {
		identity, _, reader, closeResources, err := openAuthorizedPublicationReader(ctx, openKeyring, env, session)
		if err != nil {
			return [32]byte{}, err
		}
		defer closeResources()
		head, err := service.ReadPublishedHead(ctx, service.PublicationHeadConfig{
			DID: identity.DID, Session: session.Session, Reader: reader,
		})
		if err != nil {
			return [32]byte{}, err
		}
		return head.Vault, nil
	}
}
