package api

import (
	"testing"
)

// TestHealthWatch checks the notification policy for the periodic health check: a push goes
// out exactly once, when a passing check turns failing. Every other combination is silent.
func TestHealthWatch(t *testing.T) {
	w := &HealthWatch{}
	if m := w.Tick(""); m != nil {
		t.Fatalf("first passing check pushed: %v", m)
	}
	m := w.Tick("ntfy unreadable: ntfy answered 503")
	if m == nil {
		t.Fatal("ok-to-bad transition pushed nothing")
	}
	if m.Title != "bw2fabroker check failed" {
		t.Fatalf("push title = %q", m.Title)
	}
	if m.Body != "ntfy unreadable: ntfy answered 503" || m.Priority != 4 || len(m.Tags) != 1 || m.Tags[0] != "warning" {
		t.Fatalf("push body wrong: %v", m)
	}
	if m := w.Tick("vault locked"); m != nil {
		t.Fatalf("bad-to-bad check pushed again: %v", m)
	}
	if m := w.Tick("vault locked"); m != nil {
		t.Fatalf("a second bad-to-bad check pushed: %v", m)
	}
	if m := w.Tick(""); m != nil {
		t.Fatalf("bad-to-ok recovery pushed: %v", m)
	}
	if m := w.Tick(""); m != nil {
		t.Fatalf("a passing check pushed: %v", m)
	}
	// And one more onset pushes again after recovery.
	if m := w.Tick("vault unauthenticated: bw is not logged in"); m == nil {
		t.Fatal("recovered-to-bad transition pushed nothing")
	}
}

// TestHealthWatchFirstTick checks the baseline: the broker may start into a broken state, so a
// failing first check pushes even though nothing passed before it.
func TestHealthWatchFirstTick(t *testing.T) {
	w := &HealthWatch{}
	if m := w.Tick("ntfy unreadable: refused"); m == nil {
		t.Fatal("a bad first check pushed nothing")
	}
}
