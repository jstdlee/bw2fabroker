// Package agentapi is the agent-side client for the broker's HTTP API.
// It accepts only a response that follows the contract exactly.
package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

const defaultURL = "unix:/run/bw2fabroker/agent.sock"

// Error kinds returned by Client methods.
var (
	ErrUnreachable = errors.New("cannot reach the broker")
	ErrContract    = errors.New("the broker answered outside the contract")
	ErrCatalog     = errors.New("list failed")
)

// Client talks to one broker.
type Client struct {
	HTTP  *http.Client
	Base  string
	Token string
}

// FromEnv reads BROKER_URL and BROKER_TOKEN or BROKER_TOKEN_FILE.
func FromEnv() (*Client, error) {
	tok, err := tokenFromEnv()
	if err != nil {
		return nil, err
	}
	httpc, base, err := dial(os.Getenv("BROKER_URL"))
	if err != nil {
		return nil, err
	}
	return &Client{HTTP: httpc, Base: base, Token: tok}, nil
}

func tokenFromEnv() (string, error) {
	if t := strings.TrimSpace(os.Getenv("BROKER_TOKEN")); t != "" {
		return t, nil
	}
	if p := os.Getenv("BROKER_TOKEN_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", errors.New("BROKER_TOKEN_FILE is empty")
		}
		return t, nil
	}
	return "", errors.New("set BROKER_TOKEN or BROKER_TOKEN_FILE")
}

func dial(u string) (*http.Client, string, error) {
	if u == "" {
		u = defaultURL
	}
	if path, ok := strings.CutPrefix(u, "unix:"); ok {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}
		return &http.Client{Transport: tr, Timeout: 65 * time.Second}, "http://broker", nil
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return nil, "", errors.New("BROKER_URL must be unix:/path or http(s)://host:port")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, Timeout: 65 * time.Second}, strings.TrimSuffix(u, "/"), nil
}

// Decode accepts a body only when it is exactly the four contract keys and Valid.
func Decode(raw []byte) (contract.Response, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return contract.Response{}, err
	}
	if len(keys) != 4 {
		return contract.Response{}, errors.New("wrong keys")
	}
	for _, k := range []string{"request_id", "status", "code", "value"} {
		if _, ok := keys[k]; !ok {
			return contract.Response{}, errors.New("missing key " + k)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r contract.Response
	if err := dec.Decode(&r); err != nil {
		return contract.Response{}, err
	}
	if err := r.Valid(); err != nil {
		return contract.Response{}, err
	}
	return r, nil
}

// Call performs one contract request.
func (c *Client) Call(ctx context.Context, method, path string, body []byte) (contract.Response, error) {
	raw, status, err := c.raw(ctx, method, path, body)
	if err != nil {
		return contract.Response{}, err
	}
	r, err := Decode(raw)
	if err != nil {
		return contract.Response{}, fmt.Errorf("%w (HTTP %d)", ErrContract, status)
	}
	return r, nil
}

// Catalog gets /v1/items or /v1/search. The body is names and field names only.
func (c *Client) Catalog(ctx context.Context, path string) ([]byte, error) {
	raw, status, err := c.raw(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		if r, decErr := Decode(raw); decErr == nil {
			return nil, fmt.Errorf("%w: %s", ErrCatalog, r.Status)
		}
		return nil, ErrCatalog
	}
	return raw, nil
}

// Fetch creates a request and waits until it is final.
func (c *Client) Fetch(ctx context.Context, item, field, reason string) (contract.Response, error) {
	body, err := json.Marshal(contract.Request{Item: item, Field: field, Reason: reason})
	if err != nil {
		return contract.Response{}, err
	}
	resp, err := c.Call(ctx, http.MethodPost, "/v1/requests", body)
	if err != nil {
		return contract.Response{}, err
	}
	deadline := time.Now().Add(150 * time.Second)
	for resp.Status == contract.StatusPending {
		if resp.RequestID == nil || time.Now().After(deadline) {
			return contract.Response{}, ErrContract
		}
		id := *resp.RequestID
		next, err := c.Call(ctx, http.MethodGet, "/v1/requests/"+id+"/wait", nil)
		if err != nil {
			return contract.Response{}, err
		}
		if next.RequestID != nil && *next.RequestID != id {
			return contract.Response{}, ErrContract
		}
		resp = next
	}
	return resp, nil
}

func (c *Client) raw(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, contract.MaxValueBytes*2+4096))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return raw, res.StatusCode, nil
}
