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
	ids := []string{"r_faaaaaaaaaa", "r_fbaaaaaaaaa", "r_fcaaaaaaaaa"}
	for i, st := range []string{"pending", "approving", "final"} {
		r := &Request{ID: ids[i], Agent: "x", Expires: now.Add(time.Minute)}
		if err := s.Add(r); err != nil {
			t.Fatal(err)
		}
		switch st {
		case "approving":
			if _, err := s.Claim(ids[i]); err != nil {
				t.Fatal(err)
			}
		case "final":
			if _, err := s.Finish(ids[i], contract.Denied(ids[i], contract.CodeExpired)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A canceled context drops Wait out at once: the final entry answers at once, the others
	// report that they are still waiting.
	cut, cancel := context.WithCancel(context.Background())
	cancel()
	for _, id := range []string{"r_faaaaaaaaaa", "r_fbaaaaaaaaa"} {
		if r := s.Wait(cut, id, "x", time.Second); r.Status != contract.StatusPending {
			t.Fatalf("pre-clean wait on %s: %+v", id, r)
		}
	}
	if r := s.Wait(cut, "r_fcaaaaaaaaa", "x", time.Second); r.Status != contract.StatusDenied || r.Code == nil || *r.Code != contract.CodeExpired {
		t.Fatalf("pre-clean wait on the final one: %+v", r)
	}
	if got := s.ForceClean(); got != 3 {
		t.Fatalf("force cleaned %d, want 3", got)
	}
	if s.Len() != 0 {
		t.Fatalf("store not empty: %d", s.Len())
	}
	// The clean erased everything: every id, the final one included, is unknown afterwards. That is
	// the invalidation the broker promises; a waiter that was waiting when the clean ran got the
	// denied/expired final through the wake.
	for _, id := range ids {
		if r := s.Wait(context.Background(), id, "x", time.Second); r.Status != contract.StatusDenied || r.Code == nil || *r.Code != contract.CodeUnknownRequest {
			t.Fatalf("wait on %s: want unknown_request, got %+v", id, r)
		}
	}
}
