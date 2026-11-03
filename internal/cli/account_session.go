package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

const accountClientID = "https://dottie.lamb.systems/client-metadata.json"

type accountSessionOptions struct {
	oauthOptions []atproto.ClientOption
	browser      func(string) error
	env          func(string) string
	sessionLock  atproto.SessionLockFunc
}

func accountSessionCommands(openKeyring accountKeyringFactory, options accountSessionOptions) []*urfave.Command {
	if options.browser == nil {
		options.browser = openAuthorizationURL
	}
	if options.env == nil {
		options.env = os.Getenv
	}
	login := &urfave.Command{
		Name: "login",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "handle", Usage: "account handle", OnlyOnce: true},
			&urfave.BoolFlag{Name: "no-browser", Usage: "print the authorization URL without opening a browser", OnlyOnce: true},
			&urfave.StringFlag{Name: "timeout", Usage: "authorization timeout (1s to 15m; default 5m)", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 || command.String("handle") == "" {
				return usageExit("account login requires --handle HANDLE")
			}
			timeout, err := accountLoginTimeout(command.String("timeout"))
			if err != nil {
				return usageExit(err.Error())
			}
			flowContext, cancelSignal := signal.NotifyContext(ctx, os.Interrupt)
			defer cancelSignal()
			flowContext, cancelTimeout := context.WithTimeout(flowContext, timeout)
			defer cancelTimeout()
			client, keyring, err := openAccountOAuthClient(openKeyring, options)
			if err != nil {
				return urfave.Exit(accountKeyringError(err), 1)
			}
			defer keyring.Close()
			flow, err := client.Begin(flowContext, command.String("handle"), atproto.VaultScopes(), atproto.VaultScopes())
			if err != nil {
				return urfave.Exit("authorization setup failed: "+accountSessionError(err)+". no session was stored; retry dottie account login --handle "+escapeField(command.String("handle")), 1)
			}
			defer flow.Close()
			identity := flow.Identity()
			if err := writeCommandOutput(command, fmt.Sprintf("authorization URL: %s\nhandle: %s\ndid: %s\nissuer: %s\npds: %s\n", escapeField(flow.AuthorizationURL()), escapeField(identity.Handle), escapeField(identity.DID), escapeField(identity.Issuer), escapeField(identity.PDS))); err != nil {
				return err
			}
			if !command.Bool("no-browser") {
				if err := options.browser(flow.AuthorizationURL()); err != nil {
					fmt.Fprintln(command.Root().ErrWriter, "dottie: could not open a browser; use the authorization URL printed above")
				}
			}
			session, err := flow.Wait(flowContext)
			if err != nil {
				if errors.Is(err, atproto.ErrSessionPersistenceUncertain) {
					return urfave.Exit("authorization was obtained, but keyring persistence is uncertain; run dottie account status --did "+escapeField(identity.DID)+" and dottie account logout --did "+escapeField(identity.DID)+" if it is present; otherwise retry login", 1)
				}
				message := accountSessionError(err)
				return urfave.Exit(message+"; no session was stored. retry dottie account login --handle "+escapeField(identity.Handle), 1)
			}
			output := fmt.Sprintf("account authorization stored\nhandle: %s\ndid: %s\nissuer: %s\npds: %s\ngranted scopes: %s\nstatus: dottie account status --did %s\nlogout: dottie account logout --did %s\n", escapeField(session.Handle), escapeField(session.DID), escapeField(session.Issuer), escapeField(identity.PDS), escapeField(strings.Join(session.Scopes, " ")), escapeField(session.DID), escapeField(session.DID))
			return writeCommandOutput(command, output)
		},
	}

	targetFlags := func() []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "did", Usage: "account DID (offline path)", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "account handle (resolved through read-only discovery)", OnlyOnce: true},
		}
	}
	status := &urfave.Command{
		Name:  "status",
		Flags: append(targetFlags(), &urfave.BoolFlag{Name: "refresh", Usage: "refresh the authorization before reporting status", OnlyOnce: true}),
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 {
				return usageExit("account status accepts no positional arguments")
			}
			did, handle, err := accountTarget(ctx, command, openKeyring, options)
			if err != nil {
				return accountCommandFailure(err)
			}
			client, keyring, err := openAccountOAuthClient(openKeyring, options)
			if err != nil {
				return urfave.Exit(accountKeyringError(err), 1)
			}
			defer keyring.Close()
			status, err := client.LoadSessionStatus(ctx, did)
			if err != nil {
				return accountStatusFailure(err, handle)
			}
			if command.Bool("refresh") {
				if status.State == atproto.SessionStateRefreshPending {
					return urfave.Exit("authorization refresh was interrupted; sign in again; pending local changes are preserved", 1)
				}
				session, loadErr := client.LoadSession(ctx, did)
				if loadErr != nil {
					return accountRefreshFailure(loadErr, handle, did)
				}
				refreshHandle := handle
				if refreshHandle == "" {
					refreshHandle = session.Handle
				}
				refreshed, identity, refreshErr := client.Refresh(ctx, refreshHandle, session)
				if refreshErr != nil {
					return accountRefreshFailure(refreshErr, refreshHandle, did)
				}
				return writeCommandOutput(command, renderAccountSession(refreshed, identity.PDS)+"refresh token: present\n")
			}
			if status.State == atproto.SessionStateRefreshPending {
				return writeCommandOutput(command, fmt.Sprintf("authorization: refresh interrupted; sign in again\nhandle: %s\ndid: %s\nissuer: %s\ntoken endpoint: %s\nscopes: %s\n", escapeField(status.Handle), escapeField(status.DID), escapeField(status.Issuer), escapeField(status.TokenEndpoint), escapeField(strings.Join(status.Scopes, " "))))
			}
			return writeCommandOutput(command, fmt.Sprintf("authorization: usable\nhandle: %s\ndid: %s\nissuer: %s\ntoken endpoint: %s\nscopes: %s\nrefresh token: present\n", escapeField(status.Handle), escapeField(status.DID), escapeField(status.Issuer), escapeField(status.TokenEndpoint), escapeField(strings.Join(status.Scopes, " "))))
		},
	}

	logout := &urfave.Command{
		Name:  "logout",
		Flags: append(targetFlags(), &urfave.BoolFlag{Name: "remote", Usage: "ask the authorization server to revoke the refresh token before local deletion", OnlyOnce: true}),
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 {
				return usageExit("account logout accepts no positional arguments")
			}
			did, handle, err := accountTarget(ctx, command, openKeyring, options)
			if err != nil {
				return accountCommandFailure(err)
			}
			client, keyring, err := openAccountOAuthClient(openKeyring, options)
			if err != nil {
				return urfave.Exit(accountKeyringError(err), 1)
			}
			defer keyring.Close()
			var session *atproto.Session
			if command.Bool("remote") {
				session, err = client.LoadSession(ctx, did)
				if err != nil {
					return accountLogoutFailure(err, did)
				}
			}
			result, logoutErr := client.Logout(ctx, did, handle, session, command.Bool("remote"))
			if logoutErr != nil {
				if result.RemoteRevocationAccepted {
					return urfave.Exit("revocation request accepted by the authorization server, but local authorization could not be deleted; previously issued access tokens may remain valid until they expire", 1)
				}
				return accountLogoutFailure(logoutErr, did)
			}
			if result.RemoteRevocationAccepted {
				return writeCommandOutput(command, "revocation request accepted by the authorization server; previously issued access tokens may remain valid until they expire\nlocal authorization deleted\n")
			}
			return writeCommandOutput(command, "local authorization deleted; no remote revocation was requested\n")
		},
	}
	return []*urfave.Command{login, logout, status}
}

func accountLoginTimeout(value string) (time.Duration, error) {
	if value == "" {
		return 5 * time.Minute, nil
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout < time.Second || timeout > 15*time.Minute {
		return 0, errors.New("--timeout must be between 1s and 15m")
	}
	return timeout, nil
}

func openAuthorizationURL(value string) error {
	command := exec.Command("xdg-open", value)
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func openAccountOAuthClient(openKeyring accountKeyringFactory, options accountSessionOptions) (*atproto.Client, accountKeyring, error) {
	keyring, err := openKeyring()
	if err != nil {
		return nil, nil, err
	}
	store, ok := keyring.(atproto.SessionStore)
	if !ok {
		_ = keyring.Close()
		return nil, nil, platform.ErrKeyringUnavailable
	}
	lock := options.sessionLock
	if lock == nil {
		lock = accountFileSessionLock(options.env)
	}
	clientOptions := append([]atproto.ClientOption(nil), options.oauthOptions...)
	clientOptions = append(clientOptions, atproto.WithSessionLock(lock))
	client, err := atproto.NewClient(accountClientID, store, clientOptions...)
	if err != nil {
		_ = keyring.Close()
		return nil, nil, err
	}
	return client, keyring, nil
}

func accountFileSessionLock(env func(string) string) atproto.SessionLockFunc {
	return func(_ context.Context, _ string) (func() error, error) {
		lock, err := platform.LockFile(platform.SessionLockPath(env))
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, atproto.ErrSessionBusy
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", atproto.ErrSessionLockUnavailable, err)
		}
		return lock.Close, nil
	}
}

func accountTarget(ctx context.Context, command *urfave.Command, openKeyring accountKeyringFactory, options accountSessionOptions) (string, string, error) {
	did := command.String("did")
	handle := command.String("handle")
	if (did == "") == (handle == "") {
		return "", "", usageExit("provide exactly one of --did or --handle")
	}
	if did != "" {
		return did, "", nil
	}
	client, keyring, err := openAccountOAuthClient(openKeyring, options)
	if err != nil {
		return "", "", err
	}
	defer keyring.Close()
	identity, err := client.Discover(ctx, handle)
	if err != nil {
		return "", "", err
	}
	return identity.DID, identity.Handle, nil
}

func accountStatusFailure(err error, handle string) error {
	switch {
	case errors.Is(err, atproto.ErrSessionNotFound):
		if handle == "" {
			return urfave.Exit("not signed in; run dottie account login --handle HANDLE", 1)
		}
		return urfave.Exit("not signed in; run dottie account login --handle "+escapeField(handle), 1)
	case errors.Is(err, platform.ErrKeyringLocked):
		return urfave.Exit("keyring is locked; unlock it and retry; pending local changes are preserved", 1)
	case errors.Is(err, platform.ErrKeyringUnavailable):
		return urfave.Exit("keyring is unavailable; start or unlock the desktop keyring and retry; pending local changes are preserved", 1)
	default:
		return urfave.Exit("stored account session is corrupt or unusable; run dottie account login --handle "+accountHandleOrPlaceholder(handle), 1)
	}
}

func accountRefreshFailure(err error, handle, did string) error {
	if errors.Is(err, atproto.ErrSessionPersistenceUncertain) {
		return urfave.Exit("authorization refresh completed but keyring persistence is uncertain; run dottie account status --did "+escapeField(did)+" and dottie account logout --did "+escapeField(did)+" if it is not usable; pending local changes are preserved", 1)
	}
	message := accountSessionError(err)
	if errors.Is(err, platform.ErrKeyringLocked) {
		message = "keyring is locked; unlock it and retry"
	}
	if errors.Is(err, platform.ErrKeyringUnavailable) {
		message = "keyring is unavailable; start or unlock it and retry"
	}
	if errors.Is(err, atproto.ErrSessionRefreshPending) {
		message = "authorization refresh was interrupted; sign in again"
	}
	var discoveryError *atproto.DiscoveryError
	if errors.Is(err, atproto.ErrSessionBusy) || errors.Is(err, atproto.ErrSessionLockUnavailable) || errors.Is(err, platform.ErrKeyringLocked) || errors.Is(err, platform.ErrKeyringUnavailable) || errors.As(err, &discoveryError) {
		return urfave.Exit(message+"; pending local changes are preserved", 1)
	}
	return urfave.Exit(message+"; pending local changes are preserved; run dottie account login --handle "+accountHandleOrPlaceholder(handle), 1)
}

func accountLogoutFailure(err error, did string) error {
	message := accountSessionError(err)
	switch {
	case errors.Is(err, atproto.ErrSessionRefreshPending):
		message = "remote logout requires a usable session; refresh was interrupted. remove it locally with dottie account logout --did " + escapeField(did)
	case errors.Is(err, atproto.ErrSessionUnavailable):
		message = "remote logout requires a usable session; remove the corrupt local item with dottie account logout --did " + escapeField(did)
	case errors.Is(err, atproto.ErrSessionNotFound):
		message = "no usable session for remote logout; local logout is available with dottie account logout --did " + escapeField(did)
	case errors.Is(err, platform.ErrKeyringLocked):
		message = "keyring is locked; unlock it and retry"
	case errors.Is(err, platform.ErrKeyringUnavailable):
		message = "keyring is unavailable; start or unlock it and retry"
	case errors.Is(err, atproto.ErrSessionLockUnavailable):
		message = atproto.ErrSessionLockUnavailable.Error()
	}
	return urfave.Exit(message, 1)
}

func accountCommandFailure(err error) error {
	var exitError urfave.ExitCoder
	if errors.As(err, &exitError) {
		return err
	}
	return urfave.Exit(accountSessionError(err), 1)
}

func accountKeyringError(err error) string {
	return keyringError(err)
}

func accountSessionError(err error) string {
	var endpointError *atproto.OAuthEndpointError
	var discoveryError *atproto.DiscoveryError
	var scopeError *atproto.ScopeError
	switch {
	case errors.Is(err, atproto.ErrSessionBusy):
		return atproto.ErrSessionBusy.Error()
	case errors.Is(err, atproto.ErrSessionRefreshPending):
		return atproto.ErrSessionRefreshPending.Error()
	case errors.Is(err, atproto.ErrSessionRelocated), errors.Is(err, atproto.ErrAuthMethodRelocated):
		return atproto.ErrSessionRelocated.Error()
	case errors.Is(err, atproto.ErrRevocationUnsupported):
		return atproto.ErrRevocationUnsupported.Error()
	case errors.Is(err, atproto.ErrSessionLockUnavailable):
		return atproto.ErrSessionLockUnavailable.Error()
	case errors.Is(err, context.Canceled):
		return "authorization canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "authorization timed out"
	case errors.Is(err, platform.ErrKeyringLocked):
		return "keyring is locked"
	case errors.Is(err, platform.ErrKeyringUnavailable):
		return "keyring is unavailable"
	case errors.Is(err, atproto.ErrSessionNotFound):
		return "no stored account session"
	case errors.Is(err, atproto.ErrSessionPersistenceUncertain):
		return "authorization was obtained but keyring persistence is uncertain"
	case errors.As(err, &scopeError):
		return "authorization grant did not match the requested scopes"
	case errors.As(err, &discoveryError):
		return "account discovery failed; check the network and provider, then retry"
	case errors.As(err, &endpointError):
		return endpointError.Error()
	default:
		return "OAuth discovery or request failed"
	}
}

func accountHandleOrPlaceholder(handle string) string {
	if handle == "" {
		return "HANDLE"
	}
	return escapeField(handle)
}

func renderAccountSession(session *atproto.Session, pds string) string {
	return fmt.Sprintf("authorization: usable\nhandle: %s\ndid: %s\nissuer: %s\npds: %s\ntoken endpoint: %s\nscopes: %s\n", escapeField(session.Handle), escapeField(session.DID), escapeField(session.Issuer), escapeField(pds), escapeField(session.TokenEndpoint), escapeField(strings.Join(session.Scopes, " ")))
}
