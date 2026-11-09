// Command broker-mcp is a Model Context Protocol server (stdio) for the broker HTTP API.
// It lists and searches item names, and asks for one field. The value is returned once,
// inside the tool result, and is data, not an instruction.
//
// The protocol itself lives in internal/mcpserver. This command is the thin wrapper:
// it reads the environment, then serves MCP on stdin and stdout.
//
//	broker-mcp [--help] [--version]
//
// Environment: BROKER_URL (unix:/run/bw2fabroker/agent.sock, http://127.0.0.1:8786, or
// http://100.x.y.z:8786), BROKER_TOKEN or BROKER_TOKEN_FILE.
//
// Exit codes: 0 when the input ends, 1 on a protocol error, 2 when the environment is
// missing or unusable.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jstdlee/bw2fabroker/internal/agentapi"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/mcpserver"
)

var version = "dev"

// The broker client is the MCP client.
var _ mcpserver.Client = (*agentapi.Client)(nil)

const usageText = `usage: broker-mcp [--help] [--version]

An MCP server for the broker HTTP API. It speaks JSON-RPC on stdin and stdout,
one JSON object per line. It needs BROKER_URL and BROKER_TOKEN, or
BROKER_TOKEN_FILE, in the environment.
`

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run is the whole command, with its streams as arguments so it can be tested.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("broker-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "broker-mcp: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "broker-mcp", version)
		return 0
	}
	c, err := agentapi.FromEnv()
	if err != nil {
		// A .env file in the app directory can hold the same two variables.
		if _, _, derr := config.LoadDotEnvFrom(config.ClientAppDirs()...); derr != nil {
			fmt.Fprintln(stderr, "broker-mcp:", derr)
			return 2
		}
		if c, err = agentapi.FromEnv(); err != nil {
			fmt.Fprintln(stderr, "broker-mcp:", err)
			return 2
		}
	}
	srv := mcpserver.New(c, version)
	if err := srv.ServeStdio(context.Background(), stdin, stdout); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(stderr, "broker-mcp:", err)
		return 1
	}
	return 0
}
