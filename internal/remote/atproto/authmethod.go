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
	"sync"

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
	ErrAuthMethodNonReplayable = errors.New("request body is not replayable")
)

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
	return e.Kind
}

type resourceAuthMethod struct {
	client   *Client
	handle   string
	identity Identity
	origin   string
	session  *Session
	mu       sync.Mutex
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
	return &resourceAuthMethod{client: client, handle: normalizedHandle, identity: identity, origin: origin, session: session}, nil
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

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validateSession(); err != nil {
		return nil, authMethodError(ErrAuthMethodSession, err)
	}
	if a.session.AccessToken.Reveal() == "" {
		if err := a.refresh(request.Context()); err != nil {
			return nil, authMethodError(ErrAuthMethodSession, err)
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
			return nil, authMethodError(ErrAuthMethodTransport, err)
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
			return nil, authMethodError(ErrAuthMethodTransport, readErr)
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
				return nil, authMethodError(ErrAuthMethodSession, err)
			}
			continue
		}
		return response, nil
	}
	return nil, authMethodError(ErrAuthMethodTransport, errors.New("resource request exceeded the two-attempt limit"))
}

func (a *resourceAuthMethod) refresh(ctx context.Context) error {
	refreshed, err := a.client.Refresh(ctx, a.handle, a.session)
	if err != nil {
		return err
	}
	*a.session = *refreshed
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
