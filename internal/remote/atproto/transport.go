package atproto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

type ATClientTransport struct {
	Client *atclient.APIClient
}

func NewATClientTransport(client *atclient.APIClient) *ATClientTransport {
	return &ATClientTransport{Client: client}
}

func (t *ATClientTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	request, err := t.request(method, endpoint, query, body, contentType)
	if err != nil {
		return 0, nil, err
	}
	response, err := t.Client.Do(ctx, request)
	if err != nil {
		return 0, nil, err
	}
	if response == nil || response.Body == nil {
		return 0, nil, errors.New("XRPC client returned an empty response")
	}
	defer response.Body.Close()
	const maximum = 2 << 20
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return response.StatusCode, nil, err
	}
	if len(encoded) > maximum {
		return response.StatusCode, nil, errors.New("XRPC response exceeds the JSON transport limit")
	}
	return response.StatusCode, encoded, nil
}

func (t *ATClientTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	request, err := t.request(http.MethodGet, endpoint, query, nil, "")
	if err != nil {
		return 0, nil, err
	}
	request.Headers.Set("Accept", "*/*")
	if endpoint == "com.atproto.sync.getRepo" {
		request.Headers.Set("Accept", "application/vnd.ipld.car")
	}
	response, err := t.Client.Do(ctx, request)
	if err != nil {
		return 0, nil, err
	}
	if response == nil || response.Body == nil {
		return 0, nil, errors.New("XRPC client returned an empty response")
	}
	return response.StatusCode, response.Body, nil
}

func (t *ATClientTransport) request(method, endpoint string, query url.Values, body []byte, contentType string) (*atclient.APIRequest, error) {
	if t == nil || t.Client == nil {
		return nil, errors.New("AT Protocol API client is required")
	}
	nsid, err := syntax.ParseNSID(endpoint)
	if err != nil {
		return nil, errors.New("invalid XRPC endpoint")
	}
	var input io.Reader
	if body != nil {
		input = bytes.NewReader(body)
	}
	request := atclient.NewAPIRequest(method, nsid, input)
	request.QueryParams = cloneURLValues(query)
	request.Headers.Set("Accept", "application/json")
	if contentType != "" {
		request.Headers.Set("Content-Type", contentType)
	}
	return request, nil
}

func cloneURLValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}
