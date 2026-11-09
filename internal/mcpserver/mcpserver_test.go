package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

// fakeClient is a Client that answers from memory. It never touches the network.
type fakeClient struct {
	catalog    map[string][]byte
	catalogErr error
	resp       contract.Response
	fetchErr   error
	fetched    []string
}

func (f *fakeClient) Catalog(_ context.Context, path string) ([]byte, error) {
	if f.catalogErr != nil {
		return nil, f.catalogErr
	}
	b, ok := f.catalog[path]
	if !ok {
		return nil, errors.New("no such path: " + path)
	}
	return b, nil
}

func (f *fakeClient) Fetch(_ context.Context, item, field, reason string) (contract.Response, error) {
	f.fetched = append(f.fetched, item+"/"+field+"/"+reason)
	if f.fetchErr != nil {
		return contract.Response{}, f.fetchErr
	}
	return f.resp, nil
}

// fakeURLClient is a fakeClient that also exposes a base URL.
type fakeURLClient struct {
	*fakeClient
}

func (f *fakeURLClient) BaseURL() string { return "http://broker.example" }

func newFake() *fakeClient {
	return &fakeClient{
		catalog: map[string][]byte{
			"/v1/items": []byte(`{"items":[{"id":"1","name":"staging-db","fields":["password"]},{"id":"2","name":"prod-db","fields":["password"]}]}`),
		},
		resp: contract.Approved("r_abcdefghijk", "s3cr3t-value", contract.CodeAuto),
	}
}

// call runs one request and returns the parsed response.
func call(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	out, err := s.Handle(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("no response for %s", body)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("response %s: %v", out, err)
	}
	return got
}

func result(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	got := call(t, s, body)
	res, ok := got["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", got)
	}
	return res
}

func errorCode(t *testing.T, s *Server, body string) int {
	t.Helper()
	got := call(t, s, body)
	e, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error in %v", got)
	}
	code, ok := e["code"].(float64)
	if !ok {
		t.Fatalf("no code in %v", e)
	}
	return int(code)
}

func toolResult(t *testing.T, s *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(raw)})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, s, string(body))
}

func toolBlockText(t *testing.T, tr map[string]any) string {
	t.Helper()
	content, ok := tr["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content: %v", tr["content"])
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("block: %v", content[0])
	}
	if block["type"] != "text" {
		t.Fatalf("type: %v", block["type"])
	}
	text, ok := block["text"].(string)
	if !ok {
		t.Fatalf("text: %v", block["text"])
	}
	return text
}

func TestInitialize(t *testing.T) {
	s := New(newFake(), "1.2.3")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion: %v", res["protocolVersion"])
	}
	info, ok := res["serverInfo"].(map[string]any)
	if !ok || info["name"] != "bw2fabroker" || info["version"] != "1.2.3" {
		t.Fatalf("serverInfo: %v", res["serverInfo"])
	}
	caps, ok := res["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities: %v", res["capabilities"])
	}
	for _, k := range []string{"tools", "resources", "prompts"} {
		if _, ok := caps[k]; !ok {
			t.Fatalf("capability %s missing: %v", k, caps)
		}
	}
	if txt, _ := res["instructions"].(string); !strings.Contains(txt, "request_field") {
		t.Fatalf("instructions: %v", res["instructions"])
	}
}

func TestInitializeUnknownProtocolVersion(t *testing.T) {
	s := New(newFake(), "")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if res["protocolVersion"] != protocolFallback {
		t.Fatalf("protocolVersion: %v", res["protocolVersion"])
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["version"] != "dev" {
		t.Fatalf("version: %v", info["version"])
	}
}

func TestToolsList(t *testing.T) {
	s := New(newFake(), "dev")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools, ok := res["tools"].([]any)
	if !ok {
		t.Fatalf("tools: %v", res["tools"])
	}
	got := map[string]bool{}
	for _, tv := range tools {
		tool, _ := tv.(map[string]any)
		name, _ := tool["name"].(string)
		got[name] = true
		if _, ok := tool["inputSchema"]; !ok {
			t.Fatalf("no schema for %s", name)
		}
		if d, _ := tool["description"].(string); d == "" {
			t.Fatalf("no description for %s", name)
		}
	}
	for _, want := range []string{"list_items", "search_items", "request_field", "broker_status"} {
		if !got[want] {
			t.Fatalf("tool %s missing: %v", want, got)
		}
	}
}

func TestRequestFieldApproved(t *testing.T) {
	f := newFake()
	s := New(f, "dev")
	tr := toolResult(t, s, "request_field", map[string]any{
		"item": "staging-db", "field": "password", "reason": "migrate",
	})
	if tr["isError"] != false {
		t.Fatalf("isError: %v", tr["isError"])
	}
	text := toolBlockText(t, tr)
	var got contract.Response
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("tool text %q: %v", text, err)
	}
	if got.Status != contract.StatusApproved || got.Value == nil || *got.Value != "s3cr3t-value" {
		t.Fatalf("contract: %+v", got)
	}
	if len(f.fetched) != 1 || f.fetched[0] != "staging-db/password/migrate" {
		t.Fatalf("fetched: %v", f.fetched)
	}
}

func TestRequestFieldDenied(t *testing.T) {
	f := newFake()
	f.resp = contract.Denied("r_abcdefghijk", contract.CodeDeniedByUser)
	s := New(f, "dev")
	tr := toolResult(t, s, "request_field", map[string]any{
		"item": "staging-db", "field": "password", "reason": "migrate",
	})
	if tr["isError"] != true {
		t.Fatalf("isError: %v", tr["isError"])
	}
	text := toolBlockText(t, tr)
	var got contract.Response
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("tool text %q: %v", text, err)
	}
	if got.Status != contract.StatusDenied || got.Value != nil {
		t.Fatalf("contract: %+v", got)
	}
	if strings.Contains(text, "s3cr3t-value") {
		t.Fatalf("denied result carried a value: %s", text)
	}
}

func TestRequestFieldDescription(t *testing.T) {
	s := New(newFake(), "dev")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	for _, tv := range res["tools"].([]any) {
		tool, _ := tv.(map[string]any)
		if tool["name"] != "request_field" {
			continue
		}
		d, _ := tool["description"].(string)
		for _, want := range []string{"Blocks", "expires", "exactly once"} {
			if !strings.Contains(d, want) {
				t.Fatalf("description %q misses %q", d, want)
			}
		}
		return
	}
	t.Fatal("request_field missing")
}

func TestBrokerStatus(t *testing.T) {
	s := New(newFake(), "dev")
	tr := toolResult(t, s, "broker_status", map[string]any{})
	text := toolBlockText(t, tr)
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("tool text %q: %v", text, err)
	}
	if got["reachable"] != true {
		t.Fatalf("reachable: %v", got)
	}
	if got["items"] != float64(2) {
		t.Fatalf("items: %v", got)
	}
	if got["url"] != "" {
		t.Fatalf("url: %v", got["url"])
	}
	if got["error"] != "" {
		t.Fatalf("error: %v", got["error"])
	}
	if strings.Contains(text, "s3cr3t-value") {
		t.Fatalf("status leaked a value: %s", text)
	}
}

func TestBrokerStatusWithBaseURL(t *testing.T) {
	c := &fakeURLClient{fakeClient: newFake()}
	s := New(c, "dev")
	tr := toolResult(t, s, "broker_status", map[string]any{})
	var got map[string]any
	if err := json.Unmarshal([]byte(toolBlockText(t, tr)), &got); err != nil {
		t.Fatal(err)
	}
	if got["url"] != "http://broker.example" {
		t.Fatalf("url: %v", got["url"])
	}
}

func TestBrokerStatusUnreachable(t *testing.T) {
	f := newFake()
	f.catalogErr = errors.New("cannot reach the broker")
	s := New(f, "dev")
	tr := toolResult(t, s, "broker_status", map[string]any{})
	var got map[string]any
	if err := json.Unmarshal([]byte(toolBlockText(t, tr)), &got); err != nil {
		t.Fatal(err)
	}
	if got["reachable"] != false {
		t.Fatalf("reachable: %v", got)
	}
	if got["items"] != float64(0) {
		t.Fatalf("items: %v", got)
	}
	msg, _ := got["error"].(string)
	if !strings.Contains(msg, "cannot reach the broker") {
		t.Fatalf("error: %v", got["error"])
	}
}

func TestResourcesRead(t *testing.T) {
	s := New(newFake(), "dev")
	want := map[string]string{
		"broker://contract": "POST /v1/requests",
		"broker://setup":    "mcpServers",
		"broker://fields":   "attachment:<file>",
		"broker://policy":   "denied and rejected are final",
	}
	for uri, marker := range want {
		body, err := json.Marshal(map[string]any{"uri": uri})
		if err != nil {
			t.Fatal(err)
		}
		req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": json.RawMessage(body)})
		if err != nil {
			t.Fatal(err)
		}
		res := result(t, s, string(req))
		contents, ok := res["contents"].([]any)
		if !ok || len(contents) != 1 {
			t.Fatalf("%s contents: %v", uri, res["contents"])
		}
		entry, _ := contents[0].(map[string]any)
		text, _ := entry["text"].(string)
		if !strings.Contains(text, marker) {
			t.Fatalf("%s text %q misses %q", uri, text, marker)
		}
		if entry["uri"] != uri || entry["mimeType"] != "text/plain" {
			t.Fatalf("%s entry: %v", uri, entry)
		}
	}
}

func TestResourcesReadUnknownURI(t *testing.T) {
	s := New(newFake(), "dev")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"broker://nope"}}`)
	contents, ok := res["contents"].([]any)
	if !ok || len(contents) != 0 {
		t.Fatalf("contents: %v", res["contents"])
	}
}

func TestResourcesList(t *testing.T) {
	s := New(newFake(), "dev")
	res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	resources, ok := res["resources"].([]any)
	if !ok {
		t.Fatalf("resources: %v", res["resources"])
	}
	uris := map[string]bool{}
	for _, rv := range resources {
		r, _ := rv.(map[string]any)
		uri, _ := r["uri"].(string)
		uris[uri] = true
	}
	for _, want := range []string{"broker://contract", "broker://setup", "broker://fields", "broker://policy"} {
		if !uris[want] {
			t.Fatalf("resource %s missing: %v", want, uris)
		}
	}
}

func TestPromptsGet(t *testing.T) {
	s := New(newFake(), "dev")
	for _, name := range []string{"request-field", "setup-mcp"} {
		body, err := json.Marshal(map[string]any{"name": name, "arguments": map[string]string{}})
		if err != nil {
			t.Fatal(err)
		}
		req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": json.RawMessage(body)})
		if err != nil {
			t.Fatal(err)
		}
		res := result(t, s, string(req))
		messages, ok := res["messages"].([]any)
		if !ok || len(messages) != 1 {
			t.Fatalf("%s messages: %v", name, res["messages"])
		}
		msg, _ := messages[0].(map[string]any)
		if msg["role"] != "user" {
			t.Fatalf("%s role: %v", name, msg["role"])
		}
		content, _ := msg["content"].(map[string]any)
		text, _ := content["text"].(string)
		if text == "" {
			t.Fatalf("%s text empty", name)
		}
	}
}

func TestSetupPromptText(t *testing.T) {
	s := New(newFake(), "dev")
	req := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"setup-mcp"}}`
	res := result(t, s, req)
	messages, _ := res["messages"].([]any)
	msg, _ := messages[0].(map[string]any)
	content, _ := msg["content"].(map[string]any)
	text, _ := content["text"].(string)
	for _, want := range []string{"request_field", "list_items", "Do not retry", "wait"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Fatalf("setup prompt %q misses %q", text, want)
		}
	}
}

func TestUnknownMethod(t *testing.T) {
	s := New(newFake(), "dev")
	if code := errorCode(t, s, `{"jsonrpc":"2.0","id":1,"method":"nope"}`); code != codeMethodNotFound {
		t.Fatalf("code: %d", code)
	}
}

func TestMalformedJSON(t *testing.T) {
	s := New(newFake(), "dev")
	if code := errorCode(t, s, `{"jsonrpc":`); code != codeParseError {
		t.Fatalf("code: %d", code)
	}
}

func TestNotification(t *testing.T) {
	s := New(newFake(), "dev")
	out, err := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil || out != nil {
		t.Fatalf("notification: %v %v", out, err)
	}
}

func TestPingAndLoggingSetLevel(t *testing.T) {
	s := New(newFake(), "dev")
	for _, method := range []string{"ping", "logging/setLevel"} {
		res := result(t, s, `{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`)
		if len(res) != 0 {
			t.Fatalf("%s result: %v", method, res)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	s := New(newFake(), "dev")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type: %q", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	res, ok := got["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", got)
	}
	if _, ok := res["tools"]; !ok {
		t.Fatalf("no tools: %v", res)
	}
}

func TestServeHTTPGetAndDelete(t *testing.T) {
	s := New(newFake(), "dev")
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(method, "/mcp", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status: %d", method, w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s body %q: %v", method, w.Body.String(), err)
		}
		e, ok := got["error"].(map[string]any)
		if !ok {
			t.Fatalf("%s no error: %v", method, got)
		}
		if e["code"] != float64(codeMethodNotFound) {
			t.Fatalf("%s code: %v", method, e["code"])
		}
	}
}

func TestServeHTTPNotification(t *testing.T) {
	s := New(newFake(), "dev")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	s.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status: %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("body: %q", w.Body.String())
	}
}

func TestServeStdio(t *testing.T) {
	s := New(newFake(), "dev")
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"nope"}`,
	}, "\n") + "\n"
	var out strings.Builder
	if err := s.ServeStdio(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("responses: %d\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[2], "method not found") {
		t.Fatalf("unknown method: %s", lines[2])
	}
}

// TestRequestFieldArgsKeyCompat: some clients send "args" instead of the standard
// "arguments" key (seen in production). It must still reach the tool.
func TestRequestFieldArgsKeyCompat(t *testing.T) {
	f := newFake()
	s := New(f, "dev")
	raw, err := json.Marshal(map[string]any{"name": "request_field", "args": map[string]any{
		"item": "staging-db", "field": "password", "reason": "migrate",
	}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(raw)})
	if err != nil {
		t.Fatal(err)
	}
	tr := result(t, s, string(body))
	if tr["isError"] != false {
		t.Fatalf("isError: %v", tr["isError"])
	}
	if len(f.fetched) != 1 || f.fetched[0] != "staging-db/password/migrate" {
		t.Fatalf("fetched: %v", f.fetched)
	}
}

// TestRequestFieldArgValidation: argument problems must return a precise message,
// not the opaque "invalid arguments".
func TestRequestFieldArgValidation(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing item", map[string]any{"field": "password", "reason": "migrate"}, "item and field are required"},
		{"missing reason", map[string]any{"item": "staging-db", "field": "password"}, "reason is required"},
		{"long reason", map[string]any{"item": "staging-db", "field": "password", "reason": strings.Repeat("x", 121)}, "reason too long"},
		{"url reason", map[string]any{"item": "staging-db", "field": "password", "reason": "see https://example.com"}, "must not contain a URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			s := New(f, "dev")
			tr := toolResult(t, s, "request_field", c.args)
			if tr["isError"] != true {
				t.Fatalf("isError: %v", tr["isError"])
			}
			if !strings.Contains(toolBlockText(t, tr), c.want) {
				t.Fatalf("text %q: want %q", toolBlockText(t, tr), c.want)
			}
			if len(f.fetched) != 0 {
				t.Fatalf("fetch must not run: %v", f.fetched)
			}
		})
	}
}
