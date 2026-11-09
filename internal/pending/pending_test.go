package pending

import (
	"context"
	"testing"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

func TestStore(t *testing.T) {
	s := New(nil, nil)
	now := time.Now()
	for i := 0; i < MaxPendingPerAgent; i++ {
		if err := s.Add(&Request{ID: "r_aaaaaaaaa" + string(rune('a'+i)), Agent: "x", Expires: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Add(&Request{ID: "r_bbbbbbbbbb", Agent: "x", Expires: now.Add(time.Minute)}); err != ErrTooMany {
		t.Fatalf("want ErrTooMany, got %v", err)
	}
	if err := s.Add(&Request{ID: "r_cccccccccc", Agent: "y", Expires: now.Add(50 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	// Another agent cannot wait on y's request.
	if r := s.Wait(context.Background(), "r_cccccccccc", "x", 10*time.Millisecond); r.Status != contract.StatusDenied {
		t.Fatalf("cross-agent wait: %+v", r)
	}
	if r := s.Wait(context.Background(), "r_cccccccccc", "y", time.Second); r.Code == nil || *r.Code != contract.CodeExpired {
		t.Fatalf("want expired, got %+v", r)
	}
	// Claim / Approve / deliver once.
	id := "r_aaaaaaaaaa"
	if _, err := s.Claim(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(id); err != ErrNotPending {
		t.Fatal("double claim")
	}
	if err := s.Approve(id, "v"); err != nil {
		t.Fatal(err)
	}
	if r := s.Wait(context.Background(), id, "x", time.Second); r.Status != contract.StatusApproved || *r.Value != "v" {
		t.Fatalf("approve: %+v", r)
	}
	if r := s.Wait(context.Background(), id, "x", time.Second); r.Status != contract.StatusDenied {
		t.Fatalf("delivered twice: %+v", r)
	}
}

func TestForceClean(t *testing.T) {
	now := time.Now()
	s := New(nil, nil)
	var woken []string
	for i, st := range []string{"pending", "approving", "final"} {
		id := "r_f" + string(rune('a'+i)) + "aaaaaaaa"
		r := &Request{ID: id, Agent: "x", Expires: now.Add(time.Minute)}
		if err := s.Add(r); err != nil {
			t.Fatal(err)
		}
		switch st {
		case "approving":
			if _, err := s.Claim(id); err != nil {
				t.Fatal(err)
			}
		case "final":
			if _, err := s.Finish(id, contract.Denied(id, contract.CodeExpired)); err != nil {
				t.Fatal(err)
			}
		}
		go func(rid string) {
			resp := s.Wait(context.Background(), rid, "x", time.Second)
			if resp.Status != contract.StatusDenied || *resp.Code != contract.CodeExpired {
				woken = append(woken, "bad")
			} else {
				woken = append(woken, rid)
			}
		}(id)
	}
	time.Sleep(20 * time.Millisecond)
	if got := s.ForceClean(); got != 3 {
		t.Fatalf("force cleaned %d, want 3", got)
	}
	if s.Len() != 0 {
		t.Fatalf("store not empty: %d", s.Len())
	}
	// Every waiter was woken with denied/expired, including the final one.
	for _, w := range woken {
		if w == "bad" {
			t.Fatal("a waiter did not get denied/expired")
		}
	}
	// Waiters get unknown_request after the clean.
	if r := s.Wait(context.Background(), "r_faaaaaaaaaa", "x", 10*time.Millisecond); r.Code == nil || *r.Code != contract.CodeUnknownRequest {
		t.Fatalf("want unknown_request, got %+v", r)
	}
}
