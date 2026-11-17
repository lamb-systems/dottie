package cli

import (
	"context"
	"errors"
	"fmt"

	urfave "github.com/urfave/cli/v3"
)

var errNoAuthorizedAccount = errors.New(
	"no account is authorised locally; run dottie account login --handle HANDLE or pass --did DID",
)

type ambiguousAccountError struct {
	Accounts int
}

func (e *ambiguousAccountError) Error() string {
	return fmt.Sprintf(
		"%d accounts are authorised locally; --did is required to choose the account this command acts on",
		e.Accounts,
	)
}

type sessionDIDSource func(context.Context) ([]string, error)

func productionSessionDIDSource(openKeyring accountKeyringFactory, env func(string) string) sessionDIDSource {
	return func(ctx context.Context) ([]string, error) {
		keyring, err := openKeyring()
		if err != nil {
			return nil, err
		}
		defer func() { _ = keyring.Close() }()
		client, err := newAuthorizedAccountClient(keyring, env)
		if err != nil {
			return nil, err
		}
		return client.ListSessionDIDs(ctx)
	}
}

func resolveAccountDID(ctx context.Context, command *urfave.Command, source sessionDIDSource) (bool, error) {
	if command.String("did") != "" {
		return false, nil
	}
	dids, err := source(ctx)
	if err != nil {
		return false, err
	}
	switch len(dids) {
	case 0:
		return false, errNoAuthorizedAccount
	case 1:
		if err := command.Set("did", dids[0]); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, &ambiguousAccountError{Accounts: len(dids)}
}

func accountDIDRefusal(label string, err error) error {
	message := "the stored account sessions cannot be listed; pass --did DID"
	var ambiguous *ambiguousAccountError
	if errors.Is(err, errNoAuthorizedAccount) || errors.As(err, &ambiguous) {
		message = err.Error()
	}
	return urfave.Exit(label+" refused: "+message, 3)
}

func renderResolvedAccount(did string) string {
	return "account: " + escapeField(did) + " (resolved from the only authorised session; --did was omitted)\n"
}

func writeResolvedAccount(command *urfave.Command, resolved bool) error {
	if !resolved {
		return nil
	}
	return writeCommandOutput(command, renderResolvedAccount(command.String("did")))
}
