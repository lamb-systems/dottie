# Packaging — example only

The systemd user unit is not installed or enabled. The scaffold rejects `dottie
serve` with exit status 2. The example unit does not restart on that status.
Do not enable it until the service is implemented and tested.

Finalize installation paths and supported distributions before release. Run under a
user account with the correct session/keyring environment, never as a root daemon.
Installation must not register accounts, modify preferences or start sync implicitly.
