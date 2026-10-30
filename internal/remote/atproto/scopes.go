package atproto

import (
	"errors"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strings"
)

var scopeNSID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*){2,}$`)

type ScopeError struct {
	Granted   []string
	Requested []string
	Required  []string
	Reason    string
}

func (e *ScopeError) Error() string {
	return "invalid OAuth scope grant: " + e.Reason
}

func ParseScopes(value string) ([]string, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return nil, errors.New("scope list is empty or has surrounding whitespace")
	}
	parts := strings.Split(value, " ")
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, "\t\r\n") {
			return nil, errors.New("scope list has invalid whitespace")
		}
	}
	seen := make(map[string]struct{}, len(parts))
	for _, scope := range parts {
		if !validScope(scope) {
			return nil, fmt.Errorf("invalid atproto scope %q", scope)
		}
		if _, ok := seen[scope]; ok {
			return nil, fmt.Errorf("duplicate atproto scope %q", scope)
		}
		seen[scope] = struct{}{}
	}
	sort.Strings(parts)
	return parts, nil
}

func validScope(scope string) bool {
	if scope == "atproto" {
		return true
	}
	if strings.HasPrefix(scope, "repo:") {
		return scopeNSID.MatchString(strings.TrimPrefix(scope, "repo:"))
	}
	for _, family := range []string{"transition:", "rpc:", "account:", "identity:", "include:"} {
		if strings.HasPrefix(scope, family) {
			value := strings.TrimPrefix(scope, family)
			return value != "" && !strings.ContainsAny(value, " \t\r\n")
		}
	}
	if strings.HasPrefix(scope, "blob:") {
		mediaType := strings.TrimPrefix(scope, "blob:")
		if strings.ContainsAny(mediaType, " \t\r\n") {
			return false
		}
		parsed, _, err := mime.ParseMediaType(mediaType)
		return err == nil && parsed == mediaType && strings.Contains(parsed, "/")
	}
	return false
}

func ValidateScopes(requested, required, granted []string) error {
	requestedSet, err := scopeSet(requested)
	if err != nil {
		return err
	}
	requiredSet, err := scopeSet(required)
	if err != nil {
		return err
	}
	grantedSet, err := scopeSet(granted)
	if err != nil {
		return err
	}
	for scope := range grantedSet {
		if _, ok := requestedSet[scope]; !ok {
			return &ScopeError{Granted: sortedKeys(grantedSet), Requested: sortedKeys(requestedSet), Required: sortedKeys(requiredSet), Reason: "grant contains an unrequested scope"}
		}
	}
	for scope := range requiredSet {
		if _, ok := grantedSet[scope]; !ok {
			return &ScopeError{Granted: sortedKeys(grantedSet), Requested: sortedKeys(requestedSet), Required: sortedKeys(requiredSet), Reason: "grant omits a required scope"}
		}
	}
	return nil
}

func scopeSet(scopes []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !validScope(scope) {
			return nil, fmt.Errorf("invalid atproto scope %q", scope)
		}
		if _, exists := set[scope]; exists {
			return nil, fmt.Errorf("duplicate atproto scope %q", scope)
		}
		set[scope] = struct{}{}
	}
	return set, nil
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
