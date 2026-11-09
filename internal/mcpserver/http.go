package mcpserver

import (
	"io"
	"net/http"
)

// maxHTTPBody is the largest request body the HTTP transport reads.
const maxHTTPBody = 1 << 20

// ServeHTTP serves the protocol over HTTP (MCP streamable HTTP, JSON responses).
// It answers POST with application/json. GET and DELETE answer 405 with a
// JSON-RPC error body, because this server keeps no session state.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		msg, err := rpcError(nil, codeMethodNotFound, "method not found")
		if err == nil {
			_, _ = w.Write(msg)
		}
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rpcErrorBody(nil, codeParseError, "parse error"))
		return
	}
	if len(body) > maxHTTPBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, rpcErrorBody(nil, codeParseError, "parse error"))
		return
	}
	msg, err := s.Handle(r.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, rpcErrorBody(nil, codeParseError, "parse error"))
		return
	}
	if len(msg) == 0 {
		// A notification has no answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

// writeJSON writes one JSON body.
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// rpcErrorBody builds a JSON-RPC error body and never fails.
func rpcErrorBody(id []byte, code int, msg string) []byte {
	b, err := rpcError(id, code, msg)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	return b
}
