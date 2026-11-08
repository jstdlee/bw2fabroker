package tailscale

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func fakeTailscaled(t *testing.T, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ts.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/status" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(body))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestPreflight(t *testing.T) {
	ctx := context.Background()
	sock := fakeTailscaled(t, `{"BackendState":"Running","Self":{"DNSName":"broker.tail1234.ts.net.","TailscaleIPs":["100.101.102.103","fd7a:115c:a1e0::1"]}}`)
	st, err := Preflight(ctx, NewLocalAPI(sock))
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := st.IPv4(); ip.String() != "100.101.102.103" || st.DNSName != "broker.tail1234.ts.net" {
		t.Fatalf("bad status %+v", st)
	}

	stopped := fakeTailscaled(t, `{"BackendState":"Stopped","Self":{"TailscaleIPs":[]}}`)
	if _, err := Preflight(ctx, NewLocalAPI(stopped)); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("want not connected, got %v", err)
	}
	if _, err := Preflight(ctx, NewLocalAPI(filepath.Join(t.TempDir(), "missing.sock"))); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want not running, got %v", err)
	}
}
