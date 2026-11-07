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
