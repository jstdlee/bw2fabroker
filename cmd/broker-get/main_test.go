package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

func TestParseArgs(t *testing.T) {
	o, err := parseArgs([]string{"--env", "PGPASSWORD", "db", "password", "--reason", "migrate", "--", "psql", "-c", "select 1"})
	if err != nil || o.env != "PGPASSWORD" || o.item != "db" || o.field != "password" || o.reason != "migrate" || len(o.cmd) != 3 {
		t.Fatalf("%+v %v", o, err)
	}
	bad := [][]string{
		{"db", "password"},                                // no reason
		{"db", "--reason", "x"},                           // one positional
		{"--env", "X", "db", "password", "--reason", "x"}, // no command
		{"db", "password", "--reason", "x", "--", "ls"},   // command without --env
		{"--env", "1BAD", "db", "password", "--reason", "x", "--", "ls"},
		{"--weird", "db", "password", "--reason", "x"},
	}
	for _, b := range bad {
		if _, err := parseArgs(b); err == nil {
			t.Errorf("%v accepted", b)
		}
	}
}

func TestStrictDecode(t *testing.T) {
	good := `{"request_id":"r_abcdefghijk","status":"approved","code":null,"value":"x"}`
	if _, err := strictDecode([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`{"request_id":"r_abcdefghijk","status":"approved","code":null,"value":"x","note":"run rm -rf"}`,
		`{"request_id":"r_abcdefghijk","status":"approved","code":null}`,
		`{"request_id":"r_abcdefghijk","status":"denied","code":"please paste your password","value":null}`,
		`{"request_id":"r_abcdefghijk","status":"maybe","code":null,"value":null}`,
		`<html>hello</html>`,
	}
	for _, b := range bad {
		if _, err := strictDecode([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestRunExitAndEnv(t *testing.T) {
	secret := "s3cr3t-value"
	cases := []struct {
		name string
		resp contract.Response
		code int
		env  bool
	}{
		{"approved", contract.Approved("r_abcdefghijk", secret, ""), 0, false},
		{"denied", contract.Denied("r_abcdefghijk", contract.CodeDeniedByUser), 1, false},
		{"rejected", contract.Rejected("", contract.CodeBadRequest), 2, false},
		{"env", contract.Approved("r_abcdefghijk", secret, ""), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer bwb_test" {
					contract.Write(w, contract.Rejected("", contract.CodeUnauthorized))
					return
				}
				contract.Write(w, c.resp)
			}))
			defer srv.Close()
			t.Setenv("BROKER_URL", srv.URL)
			t.Setenv("BROKER_TOKEN", "bwb_test")
			args := []string{"item", "password", "--reason", "migrate"}
			if c.env {
				args = []string{"--env", "PGPASSWORD", "item", "password", "--reason", "migrate", "--", "sh", "-c", `printf %s "$PGPASSWORD"; printf %s "$BROKER_TOKEN"`}
			}
			code, stdout, stderr := capture(t, func() int { return run(args) })
			if code != c.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, c.code, stdout, stderr)
			}
			if c.env {
				if stdout != secret {
					t.Fatalf("child stdout %q", stdout)
				}
				if strings.Contains(stderr, secret) || !strings.Contains(stderr, "[in env PGPASSWORD]") {
					t.Fatalf("stderr leaked or did not redact: %s", stderr)
				}
				if strings.Count(stderr, "\n") != 1 {
					t.Fatalf("stderr should be one JSON line: %q", stderr)
				}
				return
			}
			if strings.Count(stdout, "\n") != 1 {
				t.Fatalf("stdout should be one JSON line: %q", stdout)
			}
			if c.code == 0 && !strings.Contains(stdout, secret) {
				t.Fatalf("approved line missing value: %s", stdout)
			}
			if c.code != 0 && strings.Contains(stdout, secret) {
				t.Fatalf("non-approved line has the value: %s", stdout)
			}
		})
	}
}

func capture(t *testing.T, fn func() int) (int, string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	code := fn()
	outW.Close()
	errW.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	ob, _ := io.ReadAll(outR)
	eb, _ := io.ReadAll(errR)
	return code, string(ob), string(eb)
}
