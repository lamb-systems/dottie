package atproto

import (
	"errors"
	"testing"
)

func TestAtprotoScopeGrantExactRequiredAndRequestedRules(t *testing.T) {
	requested := []string{"atproto", "repo:systems.lamb.dottie.vaultHead", "blob:application/octet-stream"}
	if err := ValidateScopes(requested, []string{"atproto", "repo:systems.lamb.dottie.vaultHead"}, requested); err != nil {
		t.Fatalf("exact grant rejected: %v", err)
	}
	if err := ValidateScopes(requested, []string{"atproto", "repo:systems.lamb.dottie.vaultHead"}, []string{"repo:systems.lamb.dottie.vaultHead"}); err == nil {
		t.Fatal("missing required scope was accepted")
	} else {
		var scopeError *ScopeError
		if !errors.As(err, &scopeError) {
			t.Fatalf("missing scope error type = %T", err)
		}
	}
	if err := ValidateScopes(requested, []string{"atproto"}, append(requested, "repo:com.example.unrequested")); err == nil {
		t.Fatal("unrequested scope was accepted")
	}
}

func TestAtprotoScopeGrammarRejectsOpaqueOrMalformedScopes(t *testing.T) {
	for _, value := range []string{"", "repo:one.two", "repo:9one.two.three", "blob:not-a-media-type", "openid", "atproto atproto"} {
		if _, err := ParseScopes(value); err == nil {
			t.Errorf("invalid scope list %q was accepted", value)
		}
	}
	parsed, err := ParseScopes("blob:application/octet-stream repo:com.example.settings atproto")
	if err != nil || len(parsed) != 3 || parsed[0] != "atproto" {
		t.Fatalf("ParseScopes = %#v, %v", parsed, err)
	}
}
