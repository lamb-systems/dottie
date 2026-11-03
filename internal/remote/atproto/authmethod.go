package atproto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

var (
	ErrAuthMethodConfiguration = errors.New("invalid DPoP auth method configuration")
	ErrAuthMethodHost          = errors.New("request is outside the bound PDS origin")
	ErrAuthMethodSession       = errors.New("DPoP session is unavailable")
	ErrAuthMethodTransport     = errors.New("DPoP resource request failed")
	ErrAuthMethodNonce         = errors.New("DPoP nonce challenge could not be retried")
	ErrAuthMethodToken         = errors.New("invalid-token challenge could not be retried")
	ErrAuthMethodRelocated     = errors.New("discovered PDS origin changed; reconstruct the auth method")
	ErrAuthMethodNonReplayable = errors.New("request body is not replayable")
)

type AuthStatusError struct {
	StatusCode int
	Err        error
}

func (e *AuthStatusError) Error() string {
	return fmt.Sprintf("authentication request returned HTTP %d", e.StatusCode)
}

func (e *AuthStatusError) Unwrap() error {
	return e.Err
}

func authStatusFromError(err error) int {
	var status *AuthStatusError
	if errors.As(err, &status) {
		return status.StatusCode
	}
	return 0
}

type AuthMethodError struct {
	Kind error
	Err  error
}

func (e *AuthMethodError) Error() string {
	if e.Err == nil {
		return e.Kind.Error()
	}
	return e.Kind.Error() + ": " + e.Err.Error()
}

func (e *AuthMethodError) Unwrap() error {
	return errors.Join(e.Kind, e.Err)
}

type resourceAuthMethod struct {
	client   *Client
	handle   string
	identity Identity
	origin   string
	session  *Session
	mu       chan struct{}
}

func NewAuthMethod(client *Client, identity Identity, handle string, session *Session) (atclient.AuthMethod, error) {
	if client == nil || session == nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("client and session are required"))
	}
	normalizedHandle, err := normalizeHandle(handle)
	if err != nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, err)
	}
	identityHandle, err := normalizeHandle(identity.Handle)
	if err != nil || identityHandle != normalizedHandle || !validDID(identity.DID) {
		return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("handle or DID does not match discovery"))
	}
	if _, err := validateHTTPSURL(identity.Issuer); err != nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, err)
	}
	if _, err := validateHTTPSURL(identity.TokenEndpoint); err != nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, err)
	}
	origin, err := pdsHTTPSOrigin(identity.PDS)
	if err != nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, err)
	}
	if err := session.Validate(); err != nil {
		return nil, authMethodError(ErrAuthMethodSession, err)
	}
	if session.DID != identity.DID || session.Issuer != identity.Issuer || session.TokenEndpoint != identity.TokenEndpoint {
		return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("session DID, issuer or token endpoint does not match discovery"))
	}
	lock := make(chan struct{}, 1)
	lock <- struct{}{}
	return &resourceAuthMethod{client: client, handle: normalizedHandle, identity: identity, origin: origin, session: session, mu: lock}, nil
}

func (a *resourceAuthMethod) DoWithAuth(httpClient *http.Client, request *http.Request, _ syntax.NSID) (*http.Response, error) {
	if a == nil || a.client == nil || request == nil || request.URL == nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("auth method and request URL are required"))
	}
	if !requestMatchesOrigin(request, a.origin) {
		return nil, authMethodError(ErrAuthMethodHost, errors.New("only HTTPS requests to the discovered PDS origin are allowed"))
	}
	if httpClient == nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("HTTP client is required"))
	}

	select {
	case <-a.mu:
	case <-request.Context().Done():
		return nil, authMethodError(ErrAuthMethodTransport, request.Context().Err())
	}
	defer func() { a.mu <- struct{}{} }()
	if err := a.validateSession(); err != nil {
		return nil, authMethodError(ErrAuthMethodSession, err)
	}
	if a.session.AccessToken.Reveal() == "" {
		if err := a.refresh(request.Context()); err != nil {
			kind := ErrAuthMethodSession
			if errors.Is(err, ErrAuthMethodRelocated) {
				kind = ErrAuthMethodRelocated
			}
			return nil, authMethodError(kind, err)
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		attemptRequest, err := authRequestForAttempt(request, attempt)
		if err != nil {
			return nil, authMethodError(ErrAuthMethodNonReplayable, err)
		}
		if attemptRequest.Header == nil {
			attemptRequest.Header = make(http.Header)
		}
		key, err := parsePrivateKey(a.session.DPoPPrivateKey)
		if err != nil {
			return nil, authMethodError(ErrAuthMethodSession, err)
		}
		token := a.session.AccessToken
		proof, err := makeDPoPProof(key, attemptRequest.Method, attemptRequest.URL.String(), a.client.Clock(), a.client.Random, token, a.client.getNonce(a.origin))
		if err != nil {
			return nil, authMethodError(ErrAuthMethodSession, err)
		}
		attemptRequest.Header.Set("Authorization", "DPoP "+token.Reveal())
		attemptRequest.Header.Set("DPoP", proof)
		response, err := httpClient.Do(attemptRequest)
		if err != nil {
			return nil, authMethodError(ErrAuthMethodTransport, safeTransportCause(err))
		}
		if response == nil {
			return nil, authMethodError(ErrAuthMethodTransport, errors.New("HTTP client returned an empty response"))
		}
		if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusUnauthorized {
			return response, nil
		}
		body, readErr := readAndRestoreAuthBody(response)
		if readErr != nil {
			_ = response.Body.Close()
			return nil, authMethodError(ErrAuthMethodTransport, &AuthStatusError{StatusCode: response.StatusCode, Err: safeTransportCause(readErr)})
		}
		authSignal := strings.ToLower(response.Header.Get("WWW-Authenticate") + " " + string(body))
		if strings.Contains(authSignal, "use_dpop_nonce") && response.Header.Get("DPoP-Nonce") != "" {
			a.client.setNonce(a.origin, response.Header.Get("DPoP-Nonce"))
			if attempt != 0 {
				_ = response.Body.Close()
				return nil, authMethodError(ErrAuthMethodNonce, errors.New("nonce challenge persisted after the single retry"))
			}
			if !authRequestReplayable(request) {
				_ = response.Body.Close()
				return nil, authMethodError(ErrAuthMethodNonReplayable, errors.New("nonce challenge requires a retry but request body has no GetBody"))
			}
			_ = response.Body.Close()
			continue
		}
		if response.StatusCode == http.StatusUnauthorized && strings.Contains(authSignal, "invalid_token") {
			if attempt != 0 {
				_ = response.Body.Close()
				return nil, authMethodError(ErrAuthMethodToken, errors.New("invalid-token challenge persisted after the single retry"))
			}
			if !authRequestReplayable(request) {
				_ = response.Body.Close()
				return nil, authMethodError(ErrAuthMethodNonReplayable, errors.New("invalid-token challenge requires a retry but request body has no GetBody"))
			}
			_ = response.Body.Close()
			if err := a.refresh(request.Context()); err != nil {
				kind := ErrAuthMethodSession
				if errors.Is(err, ErrAuthMethodRelocated) {
					kind = ErrAuthMethodRelocated
				}
				return nil, authMethodError(kind, err)
			}
			continue
		}
		return response, nil
	}
	return nil, authMethodError(ErrAuthMethodTransport, errors.New("resource request exceeded the two-attempt limit"))
}

func (a *resourceAuthMethod) refresh(ctx context.Context) error {
	refreshed, identity, err := a.client.Refresh(ctx, a.handle, a.session)
	if err != nil {
		return err
	}
	origin, err := pdsHTTPSOrigin(identity.PDS)
	if err != nil || origin != a.origin {
		return ErrAuthMethodRelocated
	}
	*a.session = *refreshed
	a.identity = identity
	a.handle = identity.Handle
	if a.session.AccessToken.Reveal() == "" {
		return ErrSessionUnavailable
	}
	return a.validateSession()
}

func (a *resourceAuthMethod) validateSession() error {
	if err := a.session.Validate(); err != nil {
		return err
	}
	if a.session.DID != a.identity.DID || a.session.Issuer != a.identity.Issuer || a.session.TokenEndpoint != a.identity.TokenEndpoint {
		return errors.New("session DID, issuer or token endpoint changed after auth method construction")
	}
	return nil
}

func authMethodError(kind, err error) error {
	return &AuthMethodError{Kind: kind, Err: err}
}

func pdsHTTPSOrigin(value string) (string, error) {
	validated, err := validateHTTPSURL(value)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(validated)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("invalid discovered PDS origin")
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

func requestMatchesOrigin(request *http.Request, origin string) bool {
	if request.URL == nil || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
		return false
	}
	if "https://"+strings.ToLower(request.URL.Host) != origin {
		return false
	}
	return request.Host == "" || strings.EqualFold(request.Host, request.URL.Host)
}

func authRequestReplayable(request *http.Request) bool {
	return request.Body == nil || request.Body == http.NoBody || request.GetBody != nil
}

func authRequestForAttempt(request *http.Request, attempt int) (*http.Request, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	if request.Body == nil || request.Body == http.NoBody {
		copy.Body = request.Body
		return copy, nil
	}
	if attempt == 0 {
		copy.Body = request.Body
		return copy, nil
	}
	if request.GetBody == nil {
		return nil, errors.New("request body cannot be replayed")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, fmt.Errorf("reopen request body: %w", err)
	}
	copy.Body = body
	return copy, nil
}

type restoredAuthBody struct {
	io.Reader
	io.Closer
}

func readAndRestoreAuthBody(response *http.Response) ([]byte, error) {
	original := response.Body
	if original == nil {
		response.Body = http.NoBody
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(original, 4096))
	response.Body = restoredAuthBody{Reader: io.MultiReader(bytes.NewReader(body), original), Closer: original}
	return body, err
}
