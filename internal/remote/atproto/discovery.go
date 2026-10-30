package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrHandle   = errors.New("handle discovery failed")
	ErrDID      = errors.New("DID discovery failed")
	ErrPDS      = errors.New("PDS discovery failed")
	ErrResource = errors.New("protected-resource discovery failed")
	ErrIssuer   = errors.New("authorization-server discovery failed")
)

type DiscoveryError struct {
	Stage error
	Err   error
}

func (e *DiscoveryError) Error() string {
	return e.Stage.Error() + ": " + e.Err.Error()
}

func (e *DiscoveryError) Unwrap() error {
	return e.Stage
}

type Identity struct {
	Handle                string
	DID                   string
	PDS                   string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	PARSEndpoint          string
	ScopesSupported       []string
}

type didDocument struct {
	ID          string       `json:"id"`
	AlsoKnownAs []string     `json:"alsoKnownAs"`
	Service     []didService `json:"service"`
}

type didService struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

type authorizationMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	PARSEndpoint          string   `json:"pushed_authorization_request_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func (c *Client) Discover(ctx context.Context, handle string) (Identity, error) {
	handle, err := normalizeHandle(handle)
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrHandle, Err: err}
	}
	did, err := c.resolveDID(ctx, handle)
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrHandle, Err: err}
	}
	if !validDID(did) {
		return Identity{}, &DiscoveryError{Stage: ErrDID, Err: errors.New("unsupported DID form")}
	}
	didURL, err := didDocumentURL(did)
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrDID, Err: err}
	}
	var document didDocument
	if err := c.getJSON(ctx, didURL, &document); err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrDID, Err: err}
	}
	if document.ID != did {
		return Identity{}, &DiscoveryError{Stage: ErrDID, Err: errors.New("DID document id does not match the resolved DID")}
	}
	if !claimsHandle(document.AlsoKnownAs, handle) {
		return Identity{}, &DiscoveryError{Stage: ErrDID, Err: errors.New("DID document does not claim the handle")}
	}
	pds, err := pdsFromDocument(document, did)
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrPDS, Err: err}
	}
	var resource protectedResource
	resourceURL := strings.TrimRight(pds, "/") + "/.well-known/oauth-protected-resource"
	if err := c.getJSON(ctx, resourceURL, &resource); err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrResource, Err: err}
	}
	if !sameResource(resource.Resource, pds) || len(resource.AuthorizationServers) == 0 {
		return Identity{}, &DiscoveryError{Stage: ErrResource, Err: errors.New("protected-resource document does not bind the PDS or advertise an authorization server")}
	}
	server, err := validateHTTPSURL(resource.AuthorizationServers[0])
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: err}
	}
	metadataURL, err := authorizationMetadataURL(server)
	if err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: err}
	}
	var metadata authorizationMetadata
	if err := c.getJSON(ctx, metadataURL, &metadata); err != nil {
		return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: err}
	}
	if metadata.Issuer != server {
		return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: errors.New("authorization-server issuer does not match the advertised identifier")}
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.PARSEndpoint} {
		if _, err := validateHTTPSURL(endpoint); err != nil {
			return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: err}
		}
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" || metadata.PARSEndpoint == "" {
		return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: errors.New("authorization-server metadata is missing a required endpoint")}
	}
	for _, scope := range metadata.ScopesSupported {
		if strings.ContainsAny(scope, " \t\r\n") || scope == "" {
			return Identity{}, &DiscoveryError{Stage: ErrIssuer, Err: errors.New("authorization-server metadata contains a malformed scope entry")}
		}
	}
	return Identity{
		Handle:                handle,
		DID:                   did,
		PDS:                   pds,
		Issuer:                server,
		AuthorizationEndpoint: metadata.AuthorizationEndpoint,
		TokenEndpoint:         metadata.TokenEndpoint,
		PARSEndpoint:          metadata.PARSEndpoint,
		ScopesSupported:       append([]string(nil), metadata.ScopesSupported...),
	}, nil
}

func (c *Client) resolveDID(ctx context.Context, handle string) (string, error) {
	wellKnown := "https://" + handle + "/.well-known/atproto-did"
	if document, err := c.getText(ctx, wellKnown); err == nil && document != "" {
		return document, nil
	}
	lookup := c.lookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	records, err := lookup(ctx, "_atproto."+handle)
	if err != nil {
		return "", fmt.Errorf("handle DID and _atproto TXT lookup failed")
	}
	for _, record := range records {
		record = strings.TrimSpace(record)
		if strings.HasPrefix(record, "did=") && strings.TrimPrefix(record, "did=") != "" {
			return strings.TrimPrefix(record, "did="), nil
		}
	}
	return "", errors.New("handle did not publish a supported DID")
}

func (c *Client) getText(ctx context.Context, endpoint string) (string, error) {
	body, err := c.getResponseBody(ctx, endpoint)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *Client) getJSON(ctx context.Context, endpoint string, target any) error {
	body, err := c.getResponseBody(ctx, endpoint)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return errors.New("discovery response is invalid JSON")
	}
	return nil
}

func (c *Client) getResponseBody(ctx context.Context, endpoint string) ([]byte, error) {
	validated, err := validateHTTPSURL(endpoint)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, validated, nil)
	if err != nil {
		return nil, errors.New("invalid discovery request")
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, errors.New("discovery request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery endpoint returned HTTP %d", response.StatusCode)
	}
	const maximum = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(body) > maximum {
		return nil, errors.New("discovery response is unreadable or oversized")
	}
	return body, nil
}

func normalizeHandle(handle string) (string, error) {
	handle = strings.TrimSuffix(strings.TrimSpace(handle), ".")
	if handle == "" || strings.ContainsAny(handle, "/:@?#[] \\") || !strings.Contains(handle, ".") {
		return "", errors.New("invalid handle")
	}
	for _, label := range strings.Split(handle, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("invalid handle")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("invalid handle")
			}
		}
	}
	return strings.ToLower(handle), nil
}

func validDID(did string) bool {
	if strings.HasPrefix(did, "did:plc:") {
		suffix := strings.TrimPrefix(did, "did:plc:")
		return len(suffix) == 24 && isLowerAlphaNum(suffix)
	}
	if strings.HasPrefix(did, "did:web:") {
		_, err := didWebURL(did)
		return err == nil
	}
	return false
}

func isLowerAlphaNum(value string) bool {
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= '2' && ch <= '7') {
			return false
		}
	}
	return value != ""
}

func didDocumentURL(did string) (string, error) {
	if strings.HasPrefix(did, "did:plc:") && validDID(did) {
		return "https://plc.directory/" + url.PathEscape(did), nil
	}
	return didWebURL(did)
}

func didWebURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", errors.New("unsupported DID method")
	}
	parts := strings.Split(strings.TrimPrefix(did, "did:web:"), ":")
	if len(parts) == 0 || parts[0] == "" {
		return "", errors.New("invalid did:web identifier")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil || strings.ContainsAny(host, "/?#@") {
		return "", errors.New("invalid did:web host")
	}
	path := "/.well-known/did.json"
	if len(parts) > 1 {
		segments := make([]string, len(parts)-1)
		for index, part := range parts[1:] {
			decoded, decodeErr := url.PathUnescape(part)
			if decodeErr != nil || decoded == "" || decoded == "." || decoded == ".." || strings.Contains(decoded, "/") {
				return "", errors.New("invalid did:web path")
			}
			segments[index] = url.PathEscape(decoded)
		}
		path = "/" + strings.Join(segments, "/") + "/did.json"
	}
	parsed := &url.URL{Scheme: "https", Host: host, Path: path}
	if _, err := validateHTTPSURL(parsed.String()); err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func claimsHandle(names []string, handle string) bool {
	for _, name := range names {
		if strings.EqualFold(name, "at://"+handle) {
			return true
		}
	}
	return false
}

func pdsFromDocument(document didDocument, did string) (string, error) {
	var endpoint string
	for _, service := range document.Service {
		if service.ID == "#atproto_pds" || service.ID == did+"#atproto_pds" {
			if endpoint != "" {
				return "", errors.New("DID document has multiple atproto PDS services")
			}
			endpoint = service.ServiceEndpoint
		}
	}
	if endpoint == "" {
		return "", errors.New("DID document has no atproto PDS service")
	}
	return validateHTTPSURL(endpoint)
}

func validateHTTPSURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("discovered OAuth URLs must be absolute HTTPS URLs")
	}
	if parsed.RawQuery != "" {
		return "", errors.New("discovered OAuth URLs cannot contain a query")
	}
	parsed.Scheme = "https"
	return parsed.String(), nil
}

func sameResource(resource, pds string) bool {
	r, errR := url.Parse(resource)
	p, errP := url.Parse(pds)
	if errR != nil || errP != nil || r.Scheme != "https" || p.Scheme != "https" || r.User != nil || p.User != nil {
		return false
	}
	r.Host = strings.ToLower(r.Host)
	p.Host = strings.ToLower(p.Host)
	return r.Host == p.Host && cleanURLPath(r.Path) == cleanURLPath(p.Path) && r.RawQuery == "" && r.Fragment == ""
}

func cleanURLPath(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}
	return path
}

func authorizationMetadataURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid authorization-server identifier")
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" {
		parsed.Path = "/.well-known/oauth-authorization-server"
	} else {
		parsed.Path = "/.well-known/oauth-authorization-server" + path
	}
	return parsed.String(), nil
}
