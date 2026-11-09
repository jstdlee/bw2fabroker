package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/agentapi"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/mcpserver"
)

// broker returns a test broker that answers the agent API.
func broker(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bwb_test" {
			contract.Write(w, contract.Rejected("", contract.CodeUnauthorized))
			return
		}
		switch {
		case r.URL.Path == "/v1/items":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"items":[{"id":"11111111-1111-1111-1111-111111111111","name":"staging-db","folder":"agents","fields":["password"]}]}`)
		case r.URL.Path == "/v1/search":
			if r.URL.Query().Get("q") != "staging" {
				t.Errorf("q=%q", r.URL.Query().Get("q"))
			}
			io.WriteString(w, `{"items":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
			contract.Write(w, contract.Approved("r_abcdefghijk", secret, ""))
		default:
			contract.Write(w, contract.Rejected("", contract.CodeBadRequest))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// client returns a broker client for the test broker.
func client(t *testing.T, srv *httptest.Server) *agentapi.Client {
	t.Helper()
	t.Setenv("BROKER_URL", srv.URL)
	t.Setenv("BROKER_TOKEN", "bwb_test")
	c, err := agentapi.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServe(t *testing.T) {
	secret := "s3cr3t-value"
	srv := broker(t, secret)
	c := client(t, srv)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_items","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_items","arguments":{"q":"staging"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"request_field","arguments":{"item":"staging-db","field":"password","reason":"migrate"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"broker://contract"}}`,
		`{"jsonrpc":"2.0","id":7,"method":"nope"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := mcpserver.New(c, "test").ServeStdio(t.Context(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 { // initialized notification has no response
		t.Fatalf("responses: %d\n%s", len(lines), out.String())
	}
	var init struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &init); err != nil || init.Result.ProtocolVersion != "2025-03-26" {
		t.Fatalf("init: %s", lines[0])
	}
	if !strings.Contains(lines[2], "staging-db") || strings.Contains(lines[2], secret) {
		t.Fatalf("list leaked or missed: %s", lines[2])
	}
	var got struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[4]), &got); err != nil {
		t.Fatal(err)
	}
	if got.Result.IsError || len(got.Result.Content) != 1 || !strings.Contains(got.Result.Content[0].Text, secret) {
		t.Fatalf("request: %s", lines[4])
	}
	if !strings.Contains(lines[5], "POST /v1/requests") {
		t.Fatalf("resource: %s", lines[5])
	}
	if !strings.Contains(lines[6], "method not found") {
		t.Fatalf("unknown method: %s", lines[6])
	}
}

func TestServeBrokerStatus(t *testing.T) {
	secret := "s3cr3t-value"
	srv := broker(t, secret)
	c := client(t, srv)
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"broker_status","arguments":{}}}` + "\n"
	var out bytes.Buffer
	if err := mcpserver.New(c, "test").ServeStdio(t.Context(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Result.Content) != 1 {
		t.Fatalf("content: %s", out.String())
	}
	text := got.Result.Content[0].Text
	if strings.Contains(text, secret) {
		t.Fatalf("status leaked a value: %s", text)
	}
	var report struct {
		URL       string `json:"url"`
		Reachable bool   `json:"reachable"`
		Items     int    `json:"items"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatalf("report %q: %v", text, err)
	}
	if !report.Reachable || report.Items != 1 || report.Error != "" {
		t.Fatalf("report: %+v", report)
	}
}

// textOf returns the text a resource or prompt response carries.
func textOf(t *testing.T, line string) string {
	t.Helper()
	var got struct {
		Result struct {
			Contents []struct {
				Text string `json:"text"`
			} `json:"contents"`
			Messages []struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("line %q: %v", line, err)
	}
	if len(got.Result.Contents) > 0 {
		return got.Result.Contents[0].Text
	}
	if len(got.Result.Messages) > 0 {
		return got.Result.Messages[0].Content.Text
	}
	return ""
}

func TestServeNewResourcesAndPrompt(t *testing.T) {
	srv := broker(t, "s3cr3t-value")
	c := client(t, srv)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"broker://setup"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"broker://fields"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"broker://policy"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"setup-mcp"}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := mcpserver.New(c, "test").ServeStdio(t.Context(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("responses: %d\n%s", len(lines), out.String())
	}
	for i, want := range []string{"mcpServers", "attachment:<file>", "denied and rejected are final", "request_field"} {
		if !strings.Contains(textOf(t, lines[i]), want) {
			t.Fatalf("line %d misses %q: %s", i, want, lines[i])
		}
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code: %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "broker-mcp") {
		t.Fatalf("stdout: %q", stdout.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code: %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: broker-mcp") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestRunMissingEnvironment(t *testing.T) {
	t.Setenv("BROKER_URL", "")
	t.Setenv("BROKER_TOKEN", "")
	t.Setenv("BROKER_TOKEN_FILE", "")
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("code: %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "BROKER_TOKEN") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestRunEndOfInput(t *testing.T) {
	srv := broker(t, "s3cr3t-value")
	client(t, srv)
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code: %d, stderr: %s", code, stderr.String())
	}
}

func TestRunUnexpectedArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"extra"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("code: %d, stderr: %s", code, stderr.String())
	}
}
