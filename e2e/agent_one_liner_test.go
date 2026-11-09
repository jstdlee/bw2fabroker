//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/api"
)

// repoRoot is the module directory this test file ships in.
var repoRoot = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(file))
}()

// mcpCall posts one tools/call to the agent listener's /mcp route the way an
// MCP client does (argsKey selects "arguments", the legacy "args", or any other
// key a sloppy client sends) and returns the tool text plus isError.
func mcpCall(t *testing.T, srv *api.Server, tok, argsKey, reason string) (string, bool) {
	t.Helper()
	reasonPart := ""
	if reason != "" {
		reasonPart = `,"reason":"` + reason + `"`
	}
	body := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"request_field","` + argsKey + `":{"item":"` + e2eItem + `","field":"custom:api_key"` + reasonPart + `}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	srv.AgentHandler().ServeHTTP(w, req)
	var got struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("mcp response %s: %v", w.Body.String(), err)
	}
	if len(got.Result.Content) != 1 {
		t.Fatalf("mcp response has no tool text: %s", w.Body.String())
	}
	return got.Result.Content[0].Text, got.Result.IsError
}

// TestAgentOneLiner pins the agent's canonical flow end-to-end: search to learn
// the name, then ONE line that asks the broker for a field and carries the
// original task through -- CMD with the value only in the command's
// environment. The value must never reach stdout, the audit log, or the
// command output.
func TestAgentOneLiner(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain required to build broker-get")
	}
	env := startE2E(t)
	srv := env.Srv

	// .../mcp already covered in TestDisposableVault; here the CLI gets the wire.
	agentSrv := httptest.NewServer(srv.AgentHandler())
	defer agentSrv.Close()

	bin := filepath.Join(env.Dir, "broker-get")
	build := exec.Command("go", "build", "-o", bin, "./cmd/broker-get")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build broker-get: %v\n%s", err, out)
	}

	// Discovery: names and field names only.
	discovery := run(t, bin, env.Dir, env.Tok, agentSrv.URL, "search", "e2e")
	if !strings.Contains(discovery, e2eItem) || strings.Contains(discovery, e2eCustom) {
		t.Fatalf("search leaked names or values: %s", discovery)
	}

	// One line. The value arrives as APP_TOKEN in the command's env only.
	out := run(t, bin, env.Dir, env.Tok, agentSrv.URL,
		"--env", "APP_TOKEN", e2eItem, "custom:api_key",
		"--reason", "agent one-line flow test",
		"--", "sh", "-c", `test "$APP_TOKEN" = "`+e2eCustom+`" && echo FLOW_OK`)
	if !strings.Contains(out, "FLOW_OK") {
		t.Fatalf("command did not see APP_TOKEN; output:\n%s", out)
	}
	if !strings.Contains(out, `"status":"approved"`) {
		t.Fatalf("status line missing; output:\n%s", out)
	}
	if strings.Contains(out, e2eCustom) {
		t.Fatalf("value printed in plain text; output:\n%s", out)
	}

	// Wrong argument shapes still say what is wrong, from the CLI this time.
	_, err := exec.Command(bin, e2eItem, "custom:api_key", "--reason", ".").CombinedOutput()
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("unknown field must exit 2: %v", err)
	}
	assertNoSecretLeak(t, env)
}

func run(t *testing.T, bin, dir, tok, base string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "BROKER_URL="+base, "BROKER_TOKEN="+tok)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(bin), args, err, out)
	}
	if !bytes.Contains(out, []byte(e2eItem)) {
		fmt.Fprintln(os.Stderr, string(out)) // aid debugging without breaking the flow
	}
	return string(out)
}
