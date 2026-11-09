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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/jstdlee/bw2fabroker/internal/api"
	"github.com/jstdlee/bw2fabroker/internal/audit"
	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/tailscale"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// configHolder reloads the config when the file changes, so admin-panel edits
// take effect without a restart. A broken file keeps the last good config.
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
	// The credential file may hold BROKER_CONFIG itself, so read the binary and
	// working directory first, then the config directory.
	if p, n, err := config.LoadDotEnvFrom(config.AppDirs()...); err != nil {
		return fmt.Errorf("credential file: %w", err)
	} else if p != "" {
		log.Info("audit", slog.String("event", "dotenv_loaded"), slog.String("path", p), slog.Int("keys", n))
	}
	cfgPath := config.Path()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if _, err := config.ApplyEnv(cfg); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config after environment: %w", err)
	}
	if os.Geteuid() == 0 {
		log.Warn("running as root; run the broker as its own user (see deploy/)")
	}
	st0, _ := os.Stat(cfgPath)
	holder := &configHolder{path: cfgPath, cfg: cfg, mtime: st0.ModTime(), log: log}

	n, err := notify.FromConfig(cfg.Ntfy.URL, cfg.Ntfy.OwnDomain, cfg.Ntfy.Topic, cfg.Ntfy.Token)
	if err != nil {
		return fmt.Errorf("ntfy config: %w", err)
	}
	var notifier notify.Notifier
	if n == nil {
		log.Warn("no notification channel is configured; approval links go to the log and the admin panel")
	} else {
		actx, acancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = n.RequireAuth(actx)
		acancel()
		if err != nil {
			return fmt.Errorf("ntfy: %w", err)
		}
		notifier = n
	}
	push := func(m notify.Message) {
		if notifier == nil {
			return
		}
		sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = notifier.Send(sctx, m)
	}

	ts := tailscale.NewLocalAPI(cfg.Tailscale.Socket)
	pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
	mode, addr, err := chooseBind(pctx, cfg, ts)
	pcancel()
	if err != nil {
		return err
	}
	if mode == "lan" {
		log.Warn("approver is on a LAN address; any device on this network can open the approval page, which still requires the approval password", slog.String("addr", addr.String()))
	}

	linker, err := auth.NewLinker(cfg.HMACKey)
	if err != nil {
		return err
	}
	bw := vault.NewBW(cfg.Vault.BWPath, cfg.Vault.AppData)
	if err := checkVaultIsolation(cfg, log); err != nil {
		return err
	}
	if cfg.Vault.Server != "" {
		sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := bw.SetServer(sctx, cfg.Vault.Server)
		scancel()
		if err != nil {
			return fmt.Errorf("bitwarden server: %w", err)
		}
	}
	srv := api.New(holder.Get, bw, notifier, linker, log)
	srv.Version = version
	srv.Tailscale = ts
	if alog, err := audit.Open(filepath.Join(filepath.Dir(cfgPath), "audit.jsonl")); err != nil {
		return fmt.Errorf("audit log: %w", err)
	} else {
		srv.Audit = alog
		srv.Audit = alog
	}
	srv.UpdateConfig = func(fn func(*config.Config) error) error {
		c, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		if err := fn(c); err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		return config.Save(cfgPath, c)
	}
	srv.SetExposure(mode)

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
	log.Info("audit", slog.String("event", "started"), slog.String("agent_listen", cfg.Agent.Listen), slog.String("bind", addr.String()), slog.String("bind_mode", mode), slog.String("version", version))
	if cfg.Admin.Server != "" && cfg.Admin.TokenSHA256 != "" {
		mux := http.NewServeMux()
		mux.Handle("/admin", srv.AdminHandler())
		mux.Handle("/admin/", srv.AdminHandler())
		mux.Handle("/", srv.LandingHandler())
		adminHTTP := &http.Server{Addr: cfg.Admin.Server, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
		go func() {
			log.Info("audit", slog.String("event", "admin_up"), slog.String("addr", cfg.Admin.Server))
			if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin panel stopped", slog.String("error", err.Error()))
			}
		}()
		log.Info("audit", slog.String("event", "landing_up"), slog.String("url", "http://"+cfg.Admin.Server+"/"))
	} else if cfg.Admin.Server != "" {
		log.Warn("admin.server is set but there is no admin token; set BROKER_ADMIN_TOKEN or run broker init")
	}

	go manageApprover(ctx, srv, holder, ts, log)
	go syncLoop(ctx, bw, log)
	go srv.RequestCleaner(ctx)
	if mode == "lan" {
		go push(notify.Message{Title: "bw2fabroker is on the LAN", Body: "The approval page is bound to " + addr.String() + ". Any device on this network can open it. Approval still requires the approval password.", Priority: 4, Tags: []string{"warning"}})
	}

	if pw := os.Getenv("BW_MASTER_PASSWORD"); pw != "" && !bw.Unlocked() {
		if err := srv.UnlockVault(ctx, pw); err != nil {
			log.Warn("BW_MASTER_PASSWORD did not unlock the vault", slog.String("error", err.Error()))
		}
	}
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
		go push(notify.Message{Title: "bw2fabroker is locked", Body: "Run `broker unlock` on the broker host to unlock the vault.", Priority: 4, Tags: []string{"lock"}})
	}

	<-ctx.Done()
	log.Info("audit", slog.String("event", "stopping"))
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = agentSrv.Shutdown(shutdown)
	bw.Lock()
	return nil
}

// checkVaultIsolation keeps the agents account to the broker. A Bitwarden CLI data directory
// that another user on this host can read would let that user unlock the same account and read
// the items directly, without the broker and without your approval.
func checkVaultIsolation(cfg *config.Config, log *slog.Logger) error {
	if err := vault.CheckBinary(cfg.Vault.BWPath); err != nil {
		return err
	}
	dir := cfg.Vault.AppData
	if dir == "" {
		dir = vault.DefaultAppData()
	}
	if _, err := os.Stat(dir); err != nil {
		log.Warn("the Bitwarden CLI data directory does not exist yet; log in with `bw login --apikey` as this user", slog.String("path", dir))
		return nil
	}
	if vault.InContainer() {
		log.Warn("running in a container; the container is the boundary for the Bitwarden session", slog.String("path", dir))
		return nil
	}
	return vault.CheckIsolation(dir)
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

func chooseBind(ctx context.Context, cfg *config.Config, ts tailscale.Checker) (string, netip.AddrPort, error) {
	var ips []netip.Addr
	st, err := tailscale.Preflight(ctx, ts)
	if err == nil {
		ips = st.IPs
	}
	exp, berr := config.ResolveBind(ctx, cfg, ips)
	if berr != nil {
		if err != nil {
			return "", netip.AddrPort{}, err
		}
		return "", netip.AddrPort{}, berr
	}
	if exp.Mode == "tailscale" && err != nil {
		return "", netip.AddrPort{}, err
	}
	return exp.Mode, exp.Addr, nil
}

func approverAddr(cfg *config.Config, st tailscale.Status) (netip.AddrPort, error) {
	exp, err := config.ResolveBind(context.Background(), cfg, st.IPs)
	return exp.Addr, err
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
		mode, addr, err := chooseBind(c, cfg, ts)
		cancel()
		if err != nil {
			closeL(err.Error())
			srv.SetExposure("")
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
		srv.SetExposure(mode)
		srv.SetApproverBase("http://" + net.JoinHostPort(host, strconv.Itoa(int(addr.Port()))))
		log.Info("audit", slog.String("event", "approver_up"), slog.String("addr", addr.String()), slog.String("mode", mode))
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
