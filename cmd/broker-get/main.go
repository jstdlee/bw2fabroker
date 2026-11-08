// Command broker-get asks the broker for one secret and waits for the user's decision.
//
//	broker-get [--env VAR] ITEM FIELD --reason "why" [-- CMD ARGS...]
//
// It prints exactly one JSON line with the keys request_id, status, code, value.
// Without --env it prints the line on stdout and exits 0 (approved), 1 (denied), or 2 (rejected).
// With --env it puts the value only in CMD's environment, prints the line on stderr with
// value "[in env VAR]", and exits with CMD's exit status (1 or 2 when no command ran).
//
// Environment: BROKER_URL (unix:/run/bw2fabroker/agent.sock, http://127.0.0.1:8786, or
// http://100.x.y.z:8786), BROKER_TOKEN or BROKER_TOKEN_FILE.
package main

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
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

const defaultURL = "unix:/run/bw2fabroker/agent.sock"

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

type options struct {
	env, item, field, reason, query string
	list                            bool
	cmd                             []string
}

func parseArgs(args []string) (options, error) {
	var o options
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			o.cmd = args[i+1:]
			i = len(args)
		case a == "--env" || a == "--reason":
			if i+1 >= len(args) {
				return o, fmt.Errorf("%s needs a value", a)
			}
			if a == "--env" {
				o.env = args[i+1]
			} else {
				o.reason = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "--env="):
			o.env = strings.TrimPrefix(a, "--env=")
		case strings.HasPrefix(a, "--reason="):
			o.reason = strings.TrimPrefix(a, "--reason=")
		case a == "-h" || a == "--help":
			return o, errors.New("help")
		case strings.HasPrefix(a, "-") && a != "-":
			return o, fmt.Errorf("unknown option %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 1 && pos[0] == "list" {
		o.list = true
		return o, nil
	}
	if len(pos) == 2 && pos[0] == "search" {
		o.query = pos[1]
		return o, nil
	}
	if len(pos) != 2 {
		return o, errors.New("need ITEM and FIELD")
	}
	o.item, o.field = pos[0], pos[1]
	if o.reason == "" {
		return o, errors.New("--reason is required")
	}
	if o.env != "" && !envNameRe.MatchString(o.env) {
		return o, errors.New("--env needs a variable name")
	}
	if o.env != "" && len(o.cmd) == 0 {
		return o, errors.New("--env needs a command after --")
	}
	if o.env == "" && len(o.cmd) > 0 {
		return o, errors.New("a command after -- needs --env VAR")
	}
	return o, nil
}

const usageText = `usage: broker-get [--env VAR] ITEM FIELD --reason "why" [-- CMD ARGS...]
       broker-get list
       broker-get search TEXT
FIELD: username | password | totp | uri | notes | custom:<name> | card:<part> | identity:<part> | attachment:<file>
list and search print names and field names, never values.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	o, err := parseArgs(args)
	if err != nil {
		if err.Error() != "help" {
			fmt.Fprintln(os.Stderr, "broker-get:", err)
		}
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	if o.list || o.query != "" {
		return catalog(o)
	}
	resp := fetch(o)
	out := os.Stdout
	if o.env != "" {
		out = os.Stderr
	}
	if resp.Status != contract.StatusApproved {
		printLine(out, resp)
		if resp.Status == contract.StatusDenied {
			return 1
		}
		return 2
	}
	if o.env == "" {
		printLine(out, resp)
		return 0
	}
	value := *resp.Value
	shown := "[in env " + o.env + "]"
	resp.Value = &shown
	printLine(out, resp)
	return runWithEnv(o, value)
}

func printLine(w io.Writer, r contract.Response) {
	b, err := json.Marshal(r)
	if err != nil {
		b = []byte(`{"request_id":null,"status":"rejected","code":"internal_error","value":null}`)
	}
	fmt.Fprintln(w, string(b))
}

func internalErr(id string) contract.Response {
	return contract.Rejected(id, contract.CodeInternalError)
}

func runWithEnv(o options, value string) int {
	path, err := exec.LookPath(o.cmd[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get: command not found:", o.cmd[0])
		return 127
	}
	cmd := exec.Command(path, o.cmd[1:]...)
	env := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == o.env || k == "BROKER_TOKEN" || k == "BROKER_TOKEN_FILE" {
			continue // the child never gets the agent token
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, o.env+"="+value)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return 126
	}
	return 0
}

func token() (string, error) {
	if t := os.Getenv("BROKER_TOKEN"); t != "" {
		return strings.TrimSpace(t), nil
	}
	if p := os.Getenv("BROKER_TOKEN_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", errors.New("set BROKER_TOKEN or BROKER_TOKEN_FILE")
}

func client() (*http.Client, string, error) {
	u := os.Getenv("BROKER_URL")
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
	tr.Proxy = nil // the broker is local or on the tailnet; never send the token through a proxy
	return &http.Client{Transport: tr, Timeout: 65 * time.Second}, strings.TrimSuffix(u, "/"), nil
}

func catalog(o options) int {
	tok, err := token()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		return 2
	}
	c, base, err := client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		return 2
	}
	path := "/v1/items"
	if o.query != "" {
		path = "/v1/search?q=" + urlQuery(o.query)
	}
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := c.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get: cannot reach the broker:", err)
		return 2
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "broker-get: list failed")
		return 2
	}
	fmt.Println(string(raw))
	return 0
}

func urlQuery(s string) string {
	r := strings.NewReplacer(" ", "%20", "&", "%26", "?", "%3F", "#", "%23")
	return r.Replace(s)
}

func fetch(o options) contract.Response {
	tok, err := token()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		return contract.Rejected("", contract.CodeUnauthorized)
	}
	c, base, err := client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		return internalErr("")
	}
	body, _ := json.Marshal(contract.Request{Item: o.item, Field: o.field, Reason: o.reason})
	resp, ok := call(c, http.MethodPost, base+"/v1/requests", tok, body)
	if !ok {
		return internalErr("")
	}
	deadline := time.Now().Add(150 * time.Second)
	for resp.Status == contract.StatusPending {
		if resp.RequestID == nil || time.Now().After(deadline) {
			return internalErr("")
		}
		id := *resp.RequestID
		next, ok := call(c, http.MethodGet, base+"/v1/requests/"+id+"/wait", tok, nil)
		if !ok {
			return internalErr(id)
		}
		if next.RequestID != nil && *next.RequestID != id {
			return internalErr(id)
		}
		resp = next
	}
	return resp
}

// call does one request and accepts only a body that follows the contract exactly.
func call(c *http.Client, method, url, tok string, body []byte) (contract.Response, bool) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return contract.Response{}, false
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get: cannot reach the broker:", err)
		return contract.Response{}, false
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, contract.MaxValueBytes*2+1024))
	if err != nil {
		return contract.Response{}, false
	}
	r, err := strictDecode(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get: the broker answered outside the contract; ignoring it")
		return contract.Response{}, false
	}
	return r, true
}

func strictDecode(raw []byte) (contract.Response, error) {
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
