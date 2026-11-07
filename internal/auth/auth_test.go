package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("right password rejected")
	}
	if VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") {
		t.Fatal("wrong password accepted")
	}
}

func TestLinker(t *testing.T) {
	key, _ := NewKey(32)
	l, err := NewLinker(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok := l.Sign("r_requestA", now.Add(time.Minute))
	id, err := l.Verify(tok, now)
	if err != nil || id != "r_requestA" {
		t.Fatalf("verify: %v %q", err, id)
	}
	if _, err := l.Verify(tok, now.Add(2*time.Minute)); err != ErrExpiredLink {
		t.Fatalf("want expired, got %v", err)
	}
	// A link for A cannot be turned into a link for B, or given a later expiry.
	parts := strings.Split(tok, ".")
	if _, err := l.Verify("r_requestB."+parts[1]+"."+parts[2], now); err != ErrBadLink {
		t.Fatal("swapped id accepted")
	}
	if _, err := l.Verify(parts[0]+".9999999999."+parts[2], now); err != ErrBadLink {
		t.Fatal("changed expiry accepted")
	}
	other, _ := NewKey(32)
	l2, _ := NewLinker(other)
	if _, err := l2.Verify(tok, now); err != ErrBadLink {
		t.Fatal("other key accepted")
	}
}

func TestAgentToken(t *testing.T) {
	tok, hash, err := NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	if !TokenMatches(tok, hash) || TokenMatches(tok+"x", hash) {
		t.Fatal("token match wrong")
	}
	id, _ := NewRequestID()
	if !strings.HasPrefix(id, "r_") || len(id) < 20 {
		t.Fatalf("bad id %q", id)
	}
}
