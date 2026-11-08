package config

import (
	"context"
	"net/netip"
	"testing"
)

func TestClassifyAndResolve(t *testing.T) {
	ts := netip.MustParseAddr("100.64.0.2")
	lan := netip.MustParseAddr("192.168.1.9")
	pub := netip.MustParseAddr("8.8.8.8")
	if m, ok := Classify(ts); !ok || m != "tailscale" {
		t.Fatalf("tailscale %s %v", m, ok)
	}
	if m, ok := Classify(lan); !ok || m != "lan" {
		t.Fatalf("lan %s %v", m, ok)
	}
	if _, ok := Classify(pub); ok {
		t.Fatal("public accepted")
	}
	if _, ok := Classify(netip.MustParseAddr("0.0.0.0")); ok {
		t.Fatal("unspecified accepted")
	}
	c := &Config{Approver: Approver{Port: 8787}}
	c.Defaults()
	exp, err := ResolveBind(context.Background(), c, []netip.Addr{ts})
	if err != nil || exp.Mode != "tailscale" || exp.Addr.Addr() != ts {
		t.Fatal(exp, err)
	}
	c.Approver.BindHost = "broker.lan"
	prev := LookupHost
	LookupHost = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{lan}, nil }
	t.Cleanup(func() { LookupHost = prev })
	exp, err = ResolveBind(context.Background(), c, []netip.Addr{ts})
	if err != nil || exp.Mode != "lan" || exp.Addr.Addr() != lan {
		t.Fatal(exp, err)
	}
	LookupHost = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{pub}, nil }
	if _, err := ResolveBind(context.Background(), c, nil); err == nil {
		t.Fatal("public hostname accepted")
	}
}
