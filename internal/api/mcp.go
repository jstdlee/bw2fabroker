package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/mcpserver"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// mcpClient is the MCP server's view of this broker. It works in process, so the
// /mcp endpoint on the agent listener needs no second network hop and no second token.
type mcpClient struct {
	s     *Server
	agent string
}

// Catalog returns the item names and field names, never a value.
func (c *mcpClient) Catalog(ctx context.Context, path string) ([]byte, error) {
	var (
		items []vault.CatalogItem
		err   error
	)
	switch {
	case path == "/v1/items":
		items, err = c.s.Vault.List(ctx)
	case strings.HasPrefix(path, "/v1/search?q="):
		q := strings.TrimPrefix(path, "/v1/search?q=")
		if q == "" || len(q) > 200 {
			return nil, errBadRequest
		}
		if unq, e := url.QueryUnescape(q); e == nil {
			q = unq
		}
		items, err = c.s.Vault.Search(ctx, q)
	default:
		return nil, errBadRequest
	}
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []vault.CatalogItem{}
	}
	b, err := json.Marshal(catalogBody{Items: items})
	if err != nil {
		return nil, err
	}
	c.s.audit("listed", c.agent, slog.Int("count", len(items)))
	return b, nil
}

// Fetch asks for one field and waits until the request is final.
func (c *mcpClient) Fetch(ctx context.Context, item, field, reason string) (contract.Response, error) {
	body, err := json.Marshal(map[string]string{"item": item, "field": field, "reason": reason})
	if err != nil {
		return contract.Response{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/requests", bytes.NewReader(body))
	if err != nil {
		return contract.Response{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp := c.s.create(ctx, c.agent, r)
	if resp.Status != contract.StatusPending || resp.RequestID == nil {
		return resp, nil
	}
	return c.s.Store.Wait(ctx, *resp.RequestID, c.agent, c.s.Hold), nil
}

// BaseURL is the address of the agent API, without a token.
func (c *mcpClient) BaseURL() string {
	listen := c.s.Config().Agent.Listen
	switch {
	case listen == "":
		return "http://127.0.0.1:8786"
	case strings.HasPrefix(listen, "unix:"):
		return "http://127.0.0.1:8786"
	case strings.HasPrefix(listen, ":"):
		return "http://127.0.0.1" + listen
	default:
		return "http://" + listen
	}
}

// errBadRequest marks a call the broker refuses before it reaches the vault.
var errBadRequest = contractError("bad request")

type contractError string

func (e contractError) Error() string { return string(e) }

// MCPHandler serves the Model Context Protocol over HTTP on the agent listener.
// The same bearer token that opens the REST API opens this.
func (s *Server) MCPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent, ok := s.agentFromToken(r)
		if !ok {
			s.audit("unauthorized", "", slog.String("remote", r.RemoteAddr))
			writeJSONRPCError(w, http.StatusUnauthorized, -32001, "unauthorized")
			return
		}
		s.serveMCP(w, r, agent)
	})
}

// serveMCP answers one MCP request for one agent.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request, agent string) {
	if r.URL.RawQuery != "" {
		writeJSONRPCError(w, http.StatusBadRequest, -32602, "invalid params")
		return
	}
	srv := mcpserver.New(&mcpClient{s: s, agent: agent}, s.Version)
	srv.ServeHTTP(w, r)
}

// writeJSONRPCError writes one JSON-RPC error body.
func writeJSONRPCError(w http.ResponseWriter, status, code int, msg string) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": code, "message": msg}})
	if err != nil {
		body = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
