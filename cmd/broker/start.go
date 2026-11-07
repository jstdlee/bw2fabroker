package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/jstdlee/bw2fabroker/internal/api"
	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/tailscale"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// configHolder reloads the config when the file changes, so `broker agent add`, `passwd`, and
// `auto` take effect without a restart. A broken file keeps the last good config.
type configHolder struct {
	path  string
	mu    sync.Mutex
	cfg   *config.Config
	mtime time.Time
	check time.Time
	log   *slog.Logger
}

func (h *configHolder) Get() *config.Config {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Since(h.check) < time.Second {
		return h.cfg
	}
	h.check = time.Now()
	st, err := os.Stat(h.path)
	if err != nil || st.ModTime().Equal(h.mtime) {
		return h.cfg
	}
	c, err := config.Load(h.path)
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		h.log.Error("config reload failed; keeping the last good config", slog.String("error", err.Error()))
		h.mtime = st.ModTime()
		return h.cfg
	}
	h.cfg, h.mtime = c, st.ModTime()
	h.log.Info("audit", slog.String("event", "config_reloaded"))
	return h.cfg
}

func cmdStart(args []string) error {
	if len(args) > 0 {
		return errors.New("usage: broker start")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfgPath := config.Path()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		log.Warn("running as root; run the broker as its own user (see deploy/)")
	}
	st0, _ := os.Stat(cfgPath)
	holder := &configHolder{path: cfgPath, cfg: cfg, mtime: st0.ModTime(), log: log}

	// ntfy: own domain only, checked before anything starts.
	n, err := notify.New(cfg.Ntfy.URL, cfg.Ntfy.OwnDomain, cfg.Ntfy.Topic, cfg.Ntfy.Token)
	if err != nil {
		return fmt.Errorf("ntfy config: %w (run `broker ntfy set`)", err)
	}

	// Tailscale must be installed and connected.
	ts := tailscale.NewLocalAPI(cfg.Tailscale.Socket)
	pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
	tstatus, err := tailscale.Preflight(pctx, ts)
	pcancel()
	if err != nil {
		return err
	}
	if _, err := approverAddr(cfg, tstatus); err != nil {
		return err
	}

	linker, err := auth.NewLinker(cfg.HMACKey)
	if err != nil {
		return err
	}
	bw := vault.NewBW(cfg.Vault.BWPath, cfg.Vault.AppData)
	srv := api.New(holder.Get, bw, n, linker, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	adminL, err := listenAdmin(cfg.Admin.Socket)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer adminL.Close()
	go serveAdmin(ctx, adminL, srv, holder.Get)

	agentL, err := listenAgent(cfg)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	agentSrv := &http.Server{Handler: srv.AgentHandler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		if err := agentSrv.Serve(agentL); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("agent listener stopped", slog.String("error", err.Error()))
			stop()
		}
	}()
	log.Info("audit", slog.String("event", "started"), slog.String("agent_listen", cfg.Agent.Listen), slog.String("version", version))

	go manageApprover(ctx, srv, holder, ts, log)
	go syncLoop(ctx, bw, log)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		for i := 0; i < 3 && !bw.Unlocked(); i++ {
			pw, err := readSecret("Bitwarden master password of the agents account: ")
			if err != nil {
				break
			}
			if err := srv.UnlockVault(ctx, pw); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
	if !bw.Unlocked() {
		log.Warn("vault locked; run `broker unlock` (Docker: docker exec -it broker broker unlock)")
		go func() {
			sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			_ = n.Send(sctx, notify.Message{Title: "bw2fabroker is locked", Body: "Run `broker unlock` on the broker host to unlock the vault.", Priority: 4, Tags: []string{"lock"}})
		}()
	}

	<-ctx.Done()
	log.Info("audit", slog.String("event", "stopping"))
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = agentSrv.Shutdown(shutdown)
	bw.Lock()
	return nil
}

func listenAgent(cfg *config.Config) (net.Listener, error) {
	path, ok := strings.CutPrefix(cfg.Agent.Listen, "unix:")
	if !ok {
		return net.Listen("tcp", cfg.Agent.Listen)
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0o600)
	gid := cfg.Agent.SocketGID
	if gid == 0 {
		if g, err := user.LookupGroup("broker-clients"); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if gid > 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			l.Close()
			return nil, fmt.Errorf("agent socket group %d: %w", gid, err)
		}
		mode = 0o660
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "/"
}

// approverAddr picks the tailnet IP to bind: the override if it belongs to this node, else the
// node's IPv4 address.
func approverAddr(cfg *config.Config, st tailscale.Status) (netip.AddrPort, error) {
	ip, ok := st.IPv4()
	if !ok {
		return netip.AddrPort{}, tailscale.ErrNoAddress
	}
	if cfg.Approver.BindIP != "" {
		o, err := netip.ParseAddr(cfg.Approver.BindIP)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if !st.Has(o) {
			return netip.AddrPort{}, fmt.Errorf("approver.bind_ip %s is not a tailnet address of this node", o)
		}
		ip = o
	}
	return netip.AddrPortFrom(ip, uint16(cfg.Approver.Port)), nil
}

// manageApprover keeps the approver listener on the tailnet IP while Tailscale is up, and closes
// it (fail closed) when Tailscale goes down or the address changes.
func manageApprover(ctx context.Context, srv *api.Server, holder *configHolder, ts tailscale.Checker, log *slog.Logger) {
	var (
		hs   *http.Server
		bind netip.AddrPort
	)
	closeL := func(cause string) {
		if hs == nil {
			return
		}
		srv.SetApproverBase("")
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = hs.Shutdown(c)
		cancel()
		hs = nil
		log.Info("audit", slog.String("event", "approver_down"), slog.String("cause", cause))
	}
	check := func() {
		cfg := holder.Get()
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, err := tailscale.Preflight(c, ts)
		cancel()
		if err != nil {
			closeL(err.Error())
			return
		}
		addr, err := approverAddr(cfg, st)
		if err != nil {
			closeL(err.Error())
			return
		}
		if hs != nil && addr == bind {
			return
		}
		closeL("address changed")
		l, err := net.Listen("tcp", addr.String())
		if err != nil {
			log.Error("approver listen failed", slog.String("error", err.Error()))
			return
		}
		host := addr.Addr().String()
		if cfg.Approver.PublicHost != "" {
			host = cfg.Approver.PublicHost
		}
		hs = &http.Server{Handler: srv.ApproverHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 90 * time.Second}
		go func(s *http.Server) { _ = s.Serve(l) }(hs)
		bind = addr
		srv.SetApproverBase("http://" + net.JoinHostPort(host, strconv.Itoa(int(addr.Port()))))
		log.Info("audit", slog.String("event", "approver_up"), slog.String("addr", addr.String()))
	}
	check()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			closeL("stopping")
			return
		case <-t.C:
			check()
		}
	}
}

func syncLoop(ctx context.Context, bw *vault.BW, log *slog.Logger) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if bw.Unlocked() {
				if err := bw.Sync(ctx); err != nil {
					log.Warn("bw sync failed", slog.String("error", err.Error()))
				}
			}
		}
	}
}
