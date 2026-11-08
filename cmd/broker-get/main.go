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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jstdlee/bw2fabroker/internal/agentapi"
	"github.com/jstdlee/bw2fabroker/internal/contract"
)

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
func catalog(o options) int {
	c, err := agentapi.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		return 2
	}
	path := "/v1/items"
	if o.query != "" {
		path = "/v1/search?q=" + urlQuery(o.query)
	}
	raw, err := c.Catalog(context.Background(), path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
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
	c, err := agentapi.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker-get:", err)
		if strings.Contains(err.Error(), "BROKER_URL") {
			return internalErr("")
		}
		return contract.Rejected("", contract.CodeUnauthorized)
	}
	resp, err := c.Fetch(context.Background(), o.item, o.field, o.reason)
	if err != nil {
		if errors.Is(err, agentapi.ErrContract) {
			fmt.Fprintln(os.Stderr, "broker-get: the broker answered outside the contract; ignoring it")
		} else {
			fmt.Fprintln(os.Stderr, "broker-get:", err)
		}
		return internalErr("")
	}
	return resp
}

func strictDecode(raw []byte) (contract.Response, error) {
	return agentapi.Decode(raw)
}
