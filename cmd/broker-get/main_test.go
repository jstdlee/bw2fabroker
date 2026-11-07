package main

import (
	"testing"
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
