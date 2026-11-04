package atproto

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/atclient"
)

func NewSessionAPIClient(client *Client, identity Identity, handle string, session *Session) (*atclient.APIClient, error) {
	return newSessionAPIClient(client, identity, handle, session, nil)
}

func newSessionAPIClient(client *Client, identity Identity, handle string, session *Session, roundTripper http.RoundTripper) (*atclient.APIClient, error) {
	origin, err := pdsHTTPSOrigin(identity.PDS)
	if err != nil {
		return nil, authMethodError(ErrAuthMethodConfiguration, err)
	}
	auth, err := NewAuthMethod(client, identity, handle, session)
	if err != nil {
		return nil, err
	}
	if roundTripper == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, authMethodError(ErrAuthMethodConfiguration, errors.New("default HTTP transport cannot be safely cloned"))
		}
		transport := defaultTransport.Clone()
		transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		transport.TLSHandshakeTimeout = 5 * time.Second
		transport.ResponseHeaderTimeout = 10 * time.Second
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		roundTripper = transport
	}
	api := atclient.NewAPIClient(origin)
	api.Auth = auth
	api.Client = &http.Client{
		Transport: originPinnedRoundTripper{origin: origin, next: roundTripper},
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return api, nil
}

type originPinnedRoundTripper struct {
	origin string
	next   http.RoundTripper
}

func (transport originPinnedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.next == nil || request == nil || request.URL == nil || !requestMatchesOrigin(request, transport.origin) {
		return nil, authMethodError(ErrAuthMethodHost, errors.New("only HTTPS requests to the discovered PDS origin are allowed"))
	}
	return transport.next.RoundTrip(request)
}
