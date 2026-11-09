package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/tailscale"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

func cmdDoctor() error {
	failed := 0
	ok := func(msg string) { fmt.Println("ok   ", msg) }
	bad := func(msg string) { fmt.Println("FAIL ", msg); failed++ }
	warn := func(msg string) { fmt.Println("warn ", msg) }

	p := config.Path()
	cfg, err := config.Load(p)
	if err != nil {
		bad("config: " + err.Error())
		return fmt.Errorf("%d check(s) failed", failed)
	}
	ok("config " + p + " is mode 0600")
	if err := cfg.Validate(); err != nil {
		bad("config: " + err.Error())
	} else {
		ok("config values")
	}
	if st, err := os.Stat(p); err == nil {
		if sys, okk := statOwner(st); okk && sys != uint32(os.Geteuid()) {
			warn(fmt.Sprintf("config is owned by uid %d, not by the user running doctor (uid %d)", sys, os.Geteuid()))
		}
	}
	if os.Geteuid() == 0 {
		warn("running as root; run the broker as its own user (app mode) or in its container (Docker mode)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := notify.FromConfig(cfg.Ntfy.URL, cfg.Ntfy.OwnDomain, cfg.Ntfy.Topic, cfg.Ntfy.Token)
	if err != nil {
		bad("ntfy: " + err.Error())
	} else if n == nil {
		warn("ntfy is not configured; approval links go to the log and the admin panel")
	} else {
		ok("ntfy " + cfg.Ntfy.URL + " is https on the own domain " + cfg.Ntfy.OwnDomain)
		if err := n.RequireAuth(ctx); err != nil {
			bad("ntfy: " + err.Error())
		} else {
			ok("ntfy topic " + cfg.Ntfy.Topic + " rejects anonymous publish and read, and accepts the bearer token")
			if canRead, err := n.CanRead(ctx); err == nil && canRead {
				warn("the broker token can also read topic " + cfg.Ntfy.Topic + "; write-only is enough (deploy/ntfy/provision.sh sets it)")
			}
		}
	}

	st, err := tailscale.Preflight(ctx, tailscale.NewLocalAPI(cfg.Tailscale.Socket))
	if err != nil {
		bad("tailscale: " + err.Error())
	} else {
		ip, _ := st.IPv4()
		ok("tailscale running, this node is " + ip.String())
		if a, err := approverAddr(cfg, st); err != nil {
			bad("approver: " + err.Error())
		} else {
			ok("approver listener will bind " + a.String())
		}
	}

	if strings.HasPrefix(cfg.Agent.Listen, "unix:") {
		warn("agent API is a local socket; use the tailnet HTTP address and a bearer token")
	} else if cfg.AgentListenIsTailnet() {
		ok("agent API on the tailnet (" + cfg.Agent.Listen + ")")
	} else {
		ok("agent API on " + cfg.Agent.Listen)
	}
	if len(cfg.Agents) == 0 {
		warn("no agents registered; add one in the admin panel")
	}

	bw := vault.NewBW(cfg.Vault.BWPath, cfg.Vault.AppData)
	if s, err := bw.Status(ctx); err != nil {
		bad("bw: " + err.Error())
	} else if s == "unauthenticated" {
		bad("bw is not logged in; run `bw config server <url>` and `bw login --apikey` as this user, with the agents account")
	} else {
		ok("bw is logged in (" + s + ")")
	}

	if fi, err := os.Stat("/var/run/docker.sock"); err == nil && fi.Mode().Perm()&0o006 != 0 {
		warn("/var/run/docker.sock is world-accessible; anyone with Docker access is root and can read the broker")
	}

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("All checks passed.")
	return nil
}
