# Packaging — example only

The systemd user unit is not installed or enabled. The scaffold rejects `dottie
serve` with exit status 2; the example unit avoids restarting on that status.
Do not enable it until the service is implemented and tested.

Finalize installation paths and supported distributions before release. Run as a
user with the correct session/keyring environment, never as a root daemon.
Installation must not register accounts, modify preferences or start sync implicitly.
