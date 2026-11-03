package atproto

import (
	"errors"
)

const sessionEnvelopeVersion = 1

const (
	SessionStateUsable         = "usable"
	SessionStateRefreshPending = "refresh-pending"
)

type Session struct {
	DID            string
	Handle         string
	Issuer         string
	TokenEndpoint  string
	Scopes         []string
	State          string
	AccessToken    Secret
	RefreshToken   Secret
	DPoPPrivateKey Secret
}

type SessionStatus struct {
	DID           string
	Handle        string
	Issuer        string
	TokenEndpoint string
	Scopes        []string
	State         string
	HasRefresh    bool
}

type sessionEnvelope struct {
	Version        int      `json:"version"`
	DID            string   `json:"did"`
	Handle         string   `json:"handle,omitempty"`
	Issuer         string   `json:"issuer"`
	TokenEndpoint  string   `json:"token_endpoint"`
	Scopes         []string `json:"scopes"`
	State          string   `json:"state,omitempty"`
	RefreshToken   string   `json:"refresh_token,omitempty"`
	DPoPPrivateKey string   `json:"dpop_private_key,omitempty"`
}

func (s *Session) Validate() error {
	if s == nil || !validDID(s.DID) || s.Issuer == "" || s.TokenEndpoint == "" || s.RefreshToken.Reveal() == "" || s.DPoPPrivateKey.Reveal() == "" {
		return errors.New("incomplete OAuth session")
	}
	if s.State != "" && s.State != SessionStateUsable {
		return errors.New("OAuth session is not usable")
	}
	if s.Handle != "" {
		handle, err := normalizeHandle(s.Handle)
		if err != nil || handle != s.Handle {
			return errors.New("invalid OAuth session handle")
		}
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

func (e sessionEnvelope) status() (SessionStatus, error) {
	if e.Version != sessionEnvelopeVersion || !validDID(e.DID) {
		return SessionStatus{}, ErrSessionUnavailable
	}
	if e.State == "" {
		e.State = SessionStateUsable
	}
	if e.State != SessionStateUsable && e.State != SessionStateRefreshPending {
		return SessionStatus{}, ErrSessionUnavailable
	}
	if e.Handle != "" {
		handle, err := normalizeHandle(e.Handle)
		if err != nil || handle != e.Handle {
			return SessionStatus{}, ErrSessionUnavailable
		}
	}
	if _, err := validateHTTPSURL(e.Issuer); err != nil {
		return SessionStatus{}, ErrSessionUnavailable
	}
	if _, err := validateHTTPSURL(e.TokenEndpoint); err != nil {
		return SessionStatus{}, ErrSessionUnavailable
	}
	scopes, err := canonicalScopes(e.Scopes)
	if err != nil {
		return SessionStatus{}, ErrSessionUnavailable
	}
	if e.State == SessionStateUsable && (e.RefreshToken == "" || e.DPoPPrivateKey == "") {
		return SessionStatus{}, ErrSessionUnavailable
	}
	if e.State == SessionStateUsable {
		if _, err := parsePrivateKey(NewSecret(e.DPoPPrivateKey)); err != nil {
			return SessionStatus{}, ErrSessionUnavailable
		}
	}
	if e.State == SessionStateRefreshPending && (e.RefreshToken != "" || e.DPoPPrivateKey != "") {
		return SessionStatus{}, ErrSessionUnavailable
	}
	return SessionStatus{DID: e.DID, Handle: e.Handle, Issuer: e.Issuer, TokenEndpoint: e.TokenEndpoint, Scopes: scopes, State: e.State, HasRefresh: e.State == SessionStateUsable}, nil
}
