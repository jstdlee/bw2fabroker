package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

type fakeNtfy struct{ err error }

func (f fakeNtfy) RequireAuth(context.Context) error { return f.err }

type fakeVault struct {
	st  string
	err error
}

func (f fakeVault) Status(context.Context) (string, error) { return f.st, f.err }

// TestCheckHealthOnceClassifies checks that checkHealthOnce reports the right failure text and
// records the ntfy outcome: fine is empty, and every negative vault state plus an ntfy failure
// is named.
func TestCheckHealthOnceClassifies(t *testing.T) {
	for _, c := range []struct {
		name     string
		ntfy     fakeNtfy
		vault    fakeVault
		wantNote bool // the ntfy outcome recorded as passing
		want     string
	}{
		{"all fine", fakeNtfy{nil}, fakeVault{st: "unlocked"}, true, ""},
		{"ntfy fails", fakeNtfy{errors.New("ntfy answered 503")}, fakeVault{st: "unlocked"}, false,
			"ntfy unreadable: ntfy answered 503"},
		{"vault unauthenticated", fakeNtfy{nil}, fakeVault{st: "unauthenticated"}, true,
			"vault unauthenticated: bw is not logged in"},
		{"vault locked", fakeNtfy{nil}, fakeVault{st: "locked"}, true, "vault locked"},
		{"vault unreachable", fakeNtfy{nil}, fakeVault{err: errors.New("bw: exit 1")}, true,
			"vault did not answer: bw: exit 1"},
		{"both fail", fakeNtfy{errors.New("refused")}, fakeVault{st: "locked"}, false,
			"ntfy unreadable: refused; vault locked"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var noteOK bool
			got := checkHealthOnce(c.ntfy, c.vault,
				func(ok bool, _ error) { noteOK = ok },
				slog.New(slog.DiscardHandler))
			if got != c.want {
				t.Fatalf("checkHealthOnce = %q, want %q", got, c.want)
			}
			if noteOK != c.wantNote {
				t.Fatalf("ntfy outcome recorded ok=%v, want %v", noteOK, c.wantNote)
			}
		})
	}
}
