package atproto

import (
	"errors"
)

const sessionEnvelopeVersion = 1

type Session struct {
	DID            string
	Issuer         string
	TokenEndpoint  string
	Scopes         []string
	AccessToken    Secret
	RefreshToken   Secret
	DPoPPrivateKey Secret
}

type sessionEnvelope struct {
	Version        int      `json:"version"`
	DID            string   `json:"did"`
	Issuer         string   `json:"issuer"`
	TokenEndpoint  string   `json:"token_endpoint"`
	Scopes         []string `json:"scopes"`
	RefreshToken   string   `json:"refresh_token"`
	DPoPPrivateKey string   `json:"dpop_private_key"`
}

func (s *Session) Validate() error {
	if s == nil || !validDID(s.DID) || s.Issuer == "" || s.TokenEndpoint == "" || s.RefreshToken.Reveal() == "" || s.DPoPPrivateKey.Reveal() == "" {
		return errors.New("incomplete OAuth session")
	}
	if _, err := validateHTTPSURL(s.Issuer); err != nil {
		return errors.New("invalid OAuth session issuer")
	}
	if _, err := validateHTTPSURL(s.TokenEndpoint); err != nil {
		return errors.New("invalid OAuth session token endpoint")
	}
	if _, err := canonicalScopes(s.Scopes); err != nil {
		return errors.New("invalid OAuth session scopes")
	}
	if _, err := parsePrivateKey(s.DPoPPrivateKey); err != nil {
		return err
	}
	return nil
}
