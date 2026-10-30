package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

func TestLiveOAuthHarness(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_OAUTH") != "1" {
		t.Skip("set DOTTIE_LIVE_OAUTH=1 to run the owner-authorized live OAuth harness")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if handle == "" {
		t.Fatal("DOTTIE_HANDLE is required when the live OAuth harness is enabled")
	}
	keyring, err := platform.NewKeyring()
	if err != nil {
		t.Fatalf("open Secret Service keyring: %v", err)
	}
	defer keyring.Close()
	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"atproto", "repo:systems.lamb.dottie.vaultHead", "repo:systems.lamb.dottie.vaultSnapshot", "repo:systems.lamb.dottie.vaultControl", "blob:application/octet-stream"}
	if override := os.Getenv("DOTTIE_SCOPES"); override != "" {
		scopes = strings.Fields(override)
	}
	fmt.Printf("requesting scopes: %s\n", strings.Join(scopes, " "))
	identity, err := client.Discover(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := client.Begin(context.Background(), handle, scopes, scopes)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	fmt.Printf("authorization URL: %s\n", flow.AuthorizationURL())
	browser := exec.Command("xdg-open", flow.AuthorizationURL())
	if err := browser.Start(); err != nil {
		t.Fatalf("cannot start xdg-open (set BROWSER or open the URL above manually): %v", err)
	}
	if err := browser.Wait(); err != nil {
		t.Fatalf("xdg-open failed (set BROWSER or open the URL above manually): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	session, err := flow.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("OAuth identifiers: handle=%s did=%s issuer=%s pds=%s scopes=%s\n", handle, session.DID, session.Issuer, identity.PDS, strings.Join(session.Scopes, " "))

	restarted, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.LoadSession(context.Background(), session.DID)
	if err != nil {
		t.Fatalf("load session from a fresh client: %v", err)
	}
	refreshed, err := restarted.Refresh(context.Background(), handle, loaded)
	if err != nil {
		t.Fatalf("refresh from a fresh client: %v", err)
	}
	reloaded, err := restarted.LoadSession(context.Background(), session.DID)
	if err != nil {
		t.Fatalf("reload session after refresh: %v", err)
	}
	if refreshed.Issuer != session.Issuer || reloaded.DID != session.DID {
		t.Fatalf("refresh changed identity binding: issuer=%q did=%q", refreshed.Issuer, reloaded.DID)
	}
	fmt.Printf("restart=ok refreshed=ok issuer=%s did=%s scopes=%d\n", refreshed.Issuer, reloaded.DID, len(reloaded.Scopes))
}
