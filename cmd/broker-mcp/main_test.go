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
)

func TestServe(t *testing.T) {
	secret := "s3cr3t-value"
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
	defer srv.Close()
	t.Setenv("BROKER_URL", srv.URL)
	t.Setenv("BROKER_TOKEN", "bwb_test")
	c, err := agentapi.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
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
	if err := serve(strings.NewReader(in), &out, c); err != nil {
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
