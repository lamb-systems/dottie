package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

var errPDSResponseTooLarge = errors.New("PDS response body exceeds the configured limit")

const pdsMaxResponseBody = 2 << 20

func newPDSAPIClient(pds string, auth atclient.AuthMethod, base http.RoundTripper) (*atclient.APIClient, error) {
	origin, err := pdsOrigin(pds)
	if err != nil {
		return nil, err
	}
	if base == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		transport.TLSHandshakeTimeout = 5 * time.Second
		transport.ResponseHeaderTimeout = 10 * time.Second
		transport.ExpectContinueTimeout = time.Second
		transport.IdleConnTimeout = 30 * time.Second
		base = transport
	}
	httpClient := &http.Client{
		Transport:     &pdsPolicyTransport{base: base, origin: origin, bodyLimit: pdsMaxResponseBody},
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	api := atclient.NewAPIClient(origin)
	api.Client = httpClient
	api.Auth = auth
	return api, nil
}

func pdsOrigin(pds string) (string, error) {
	parsed, err := url.Parse(pds)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("PDS origin must be an absolute HTTPS URL")
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

type pdsPolicyTransport struct {
	base      http.RoundTripper
	origin    string
	bodyLimit int64
}

func (t *pdsPolicyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil || "https://"+strings.ToLower(request.URL.Host) != t.origin {
		return nil, fmt.Errorf("request is outside the discovered TLS-only PDS origin")
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		response.Body = &boundedPDSBody{body: response.Body, limit: t.bodyLimit}
	}
	return response, nil
}

type boundedPDSBody struct {
	body  io.ReadCloser
	limit int64
	read  int64
}

func (b *boundedPDSBody) Read(buffer []byte) (int, error) {
	if b.read < b.limit {
		if int64(len(buffer)) > b.limit-b.read {
			buffer = buffer[:b.limit-b.read]
		}
		count, err := b.body.Read(buffer)
		b.read += int64(count)
		return count, err
	}
	var probe [1]byte
	count, err := b.body.Read(probe[:])
	if count != 0 {
		return 0, errPDSResponseTooLarge
	}
	return 0, err
}

func (b *boundedPDSBody) Close() error {
	return b.body.Close()
}

func pdsRequest(method, endpoint string, query url.Values, body []byte, contentType string) (*atclient.APIRequest, error) {
	var reader io.Reader
	var getBody func() (io.ReadCloser, error)
	if body != nil {
		reader = bytes.NewReader(body)
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return pdsRequestStream(method, endpoint, query, reader, getBody, contentType)
}

func pdsRequestStream(method, endpoint string, query url.Values, body io.Reader, getBody func() (io.ReadCloser, error), contentType string) (*atclient.APIRequest, error) {
	nsid, err := syntax.ParseNSID(endpoint)
	if err != nil {
		return nil, err
	}
	request := atclient.NewAPIRequest(method, nsid, body)
	request.GetBody = getBody
	request.QueryParams = query
	if contentType != "" {
		request.Headers.Set("Content-Type", contentType)
	}
	return request, nil
}

func pdsDo(ctx context.Context, api *atclient.APIClient, method, endpoint string, query url.Values, body []byte, contentType string) (*http.Response, []byte, time.Duration, error) {
	request, err := pdsRequest(method, endpoint, query, body, contentType)
	if err != nil {
		return nil, nil, 0, err
	}
	return pdsDoRequest(ctx, api, request)
}

func pdsDoStream(ctx context.Context, api *atclient.APIClient, method, endpoint string, query url.Values, body io.Reader, getBody func() (io.ReadCloser, error), contentType string) (*http.Response, []byte, time.Duration, error) {
	request, err := pdsRequestStream(method, endpoint, query, body, getBody, contentType)
	if err != nil {
		return nil, nil, 0, err
	}
	return pdsDoRequest(ctx, api, request)
}

func pdsDoRequest(ctx context.Context, api *atclient.APIClient, request *atclient.APIRequest) (*http.Response, []byte, time.Duration, error) {
	started := time.Now()
	response, err := api.Do(ctx, request)
	duration := time.Since(started)
	if err != nil {
		return nil, nil, duration, err
	}
	if response.Body == nil {
		return response, nil, duration, nil
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(response.Body)
	return response, data, duration, readErr
}

func TestPDSAPIClientDoesNotFollowRedirect(t *testing.T) {
	followed := 0
	server := newTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/xrpc/com.atproto.server.describeServer" {
			http.Redirect(writer, request, "/followed", http.StatusFound)
			return
		}
		if request.URL.Path == "/followed" {
			followed++
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(writer, request)
	}))
	api, err := newPDSAPIClient(server.URL, nil, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	response, _, _, err := pdsDo(context.Background(), api, http.MethodGet, "com.atproto.server.describeServer", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || followed != 0 {
		t.Fatalf("redirect response status=%d followed=%d", response.StatusCode, followed)
	}
}

func TestPDSAPIClientBoundsResponseBodies(t *testing.T) {
	server := newTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", pdsMaxResponseBody+1))
	}))
	api, err := newPDSAPIClient(server.URL, nil, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = pdsDo(context.Background(), api, http.MethodGet, "com.atproto.server.describeServer", nil, nil, "")
	if !errors.Is(err, errPDSResponseTooLarge) {
		t.Fatalf("bounded response error = %v", err)
	}
}

func newTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}
