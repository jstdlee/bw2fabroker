package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/api"
	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/vault/vaulttest"
)

// Demo-only secrets. They are not from a vault and are printed at startup.
const (
	demoPassword = "demo-password"
	idStaging    = "a1000000-0000-4000-8000-000000000001"
	idOpenAI     = "a1000000-0000-4000-8000-000000000002"
	idLogin      = "a1000000-0000-4000-8000-000000000003"
	idWeather    = "a1000000-0000-4000-8000-000000000004"
)

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	agentListen := fs.String("agent", "127.0.0.1:8786", "agent API listen address (loopback only)")
	approverListen := fs.String("approver", "127.0.0.1:8787", "approval page listen address (loopback only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: broker demo [--agent 127.0.0.1:8786] [--approver 127.0.0.1:8787]")
	}
	if err := loopbackOnly(*agentListen); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	if err := loopbackOnly(*approverListen); err != nil {
		return fmt.Errorf("approver: %w", err)
	}

	key, err := auth.NewKey(32)
	if err != nil {
		return err
	}
	pwHash, err := auth.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	token, hash, err := auth.NewAgentToken()
	if err != nil {
		return err
	}
	cfg := &config.Config{
		HMACKey: key, ApprovalPassword: pwHash,
		Agents: map[string]config.Agent{"demo": {TokenSHA256: hash, Created: time.Now()}},
		Auto:   []config.AutoRule{{ItemID: idWeather, Field: "custom:api_key"}},
	}
	cfg.Defaults()
	cfg.Agent.Listen = *agentListen

	vault := &vaulttest.Fake{Items: []vaulttest.Item{
		{ID: idStaging, Name: "staging-db", Folder: "demo", Fields: map[string]string{
			"username": "demo-app", "password": "demo-staging-db-password"}},
		{ID: idOpenAI, Name: "openai", Folder: "demo", Fields: map[string]string{
			"password": "sk-demo-not-a-real-key"}},
		{ID: idLogin, Name: "login", Folder: "demo", Fields: map[string]string{
			"username": "demo-user", "totp": "424242"}},
		{ID: idWeather, Name: "weather", Folder: "demo", Fields: map[string]string{
			"custom:api_key": "demo-weather-key", "totp": "111111"}},
	}}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	linker, err := auth.NewLinker(key)
	if err != nil {
		return err
	}
	inbox := &demoInbox{}
	srv := api.New(func() *config.Config { return cfg }, vault, inbox, linker, log)
	srv.AllowLoopback = true

	agentL, err := net.Listen("tcp", *agentListen)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	defer agentL.Close()
	approverL, err := net.Listen("tcp", *approverListen)
	if err != nil {
		return fmt.Errorf("approver listener: %w", err)
	}
	defer approverL.Close()

	base := "http://" + approverL.Addr().String()
	srv.SetApproverBase(base)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agentSrv := &http.Server{Handler: srv.AgentHandler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 120 * time.Second}
	approverSrv := &http.Server{Handler: inbox.wrap(srv.ApproverHandler()), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 70 * time.Second}
	go func() {
		if err := agentSrv.Serve(agentL); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("agent listener stopped", slog.String("error", err.Error()))
			stop()
		}
	}()
	go func() {
		if err := approverSrv.Serve(approverL); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("approver listener stopped", slog.String("error", err.Error()))
			stop()
		}
	}()

	fmt.Printf(`bw2fabroker DEMO
This is a fake vault on this machine. It is not Bitwarden, not Tailscale, and not ntfy.

Approval password: %s
Agent token:       %s
BROKER_URL=http://%s
Approval page:     %s/

Items (ask unless noted):
  staging-db   username, password
  openai       password
  login        username, totp
  weather      custom:api_key  (auto, no prompt)   totp still asks

Try:
  BROKER_TOKEN=%s BROKER_URL=http://%s ./bin/broker-get staging-db password --reason "try the demo approval page"

Open the approval page, or the link printed here when a request arrives. Ctrl-C stops the demo.
`, demoPassword, token, agentL.Addr().String(), base, token, agentL.Addr().String())

	log.Info("audit", slog.String("event", "demo_started"), slog.String("agent_listen", agentL.Addr().String()), slog.String("version", version))
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = agentSrv.Shutdown(shutdown)
	_ = approverSrv.Shutdown(shutdown)
	return nil
}

func loopbackOnly(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return fmt.Errorf("%s is not host:port", addr)
	}
	if !ap.Addr().IsLoopback() {
		return fmt.Errorf("%s is not a loopback address; the demo refuses other interfaces", addr)
	}
	return nil
}

type demoNotice struct {
	Title, Body, Click string
	At                 time.Time
}

// demoInbox stands in for ntfy: it prints the approval link and lists it on GET /.
type demoInbox struct {
	mu    sync.Mutex
	items []demoNotice
}

func (d *demoInbox) Send(_ context.Context, m notify.Message) error {
	fmt.Printf("\nDEMO push: %s\n%s\n", m.Title, m.Body)
	if m.Click != "" {
		fmt.Printf("%s\n", m.Click)
	}
	d.mu.Lock()
	d.items = append(d.items, demoNotice{Title: m.Title, Body: m.Body, Click: m.Click, At: time.Now()})
	if len(d.items) > 20 {
		d.items = d.items[len(d.items)-20:]
	}
	d.mu.Unlock()
	return nil
}

func (d *demoInbox) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip, ipErr := netip.ParseAddr(host)
			if err != nil || ipErr != nil || !ip.IsLoopback() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			d.page(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var inboxPage = template.Must(template.New("inbox").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>bw2fabroker demo</title>
<style>
:root{color-scheme:light;--bg:#f5f5f7;--fg:#1d1d1f;--muted:#6e6e73}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.47 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:36rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}
h1{font-size:2rem;font-weight:700;letter-spacing:-.022em;line-height:1.1;margin:0 0 .4rem}
li{background:#fff;border-radius:18px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 12px 32px rgba(0,0,0,.06);list-style:none;padding:1rem 1.1rem;margin:0 0 .8rem}
ul{padding:0}
.small{color:var(--muted);font-size:.9rem}
a{color:#0071e3}
</style></head><body><main>
<h1>bw2fabroker demo</h1>
<p class="small">Fake vault. Approval password was printed in the terminal that started <code>broker demo</code>. This page is not ntfy.</p>
{{if .}}
<ul>
{{range .}}
<li><strong>{{.Title}}</strong><br>{{.Body}}
{{if .Click}}<br><a href="{{.Click}}">Open approval</a>{{end}}
<span class="small"><br>{{.At.Format "15:04:05"}}</span></li>
{{end}}
</ul>
{{else}}
<p>No requests yet. Ask with <code>broker-get</code>; the link shows up here.</p>
{{end}}
</main></body></html>`))

func (d *demoInbox) page(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	items := append([]demoNotice(nil), d.items...)
	d.mu.Unlock()
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_ = inboxPage.Execute(w, items)
}
