// Command broker is the bw2fabroker server. Administration is the loopback panel.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

var version = "dev"

const usage = `broker: Bitwarden access broker with phone approval

Setup:
  broker init [--ntfy-domain ntfy.example.com]   create config and the loopback admin panel
                                                 (omit --ntfy-domain to run without notifications)
  broker login [--email you@example.com]         log in the agents account for this profile
                                                 (API key unless --email; bw prompts for the rest)

Run:
  broker start                start serving (asks for the bw master password on a terminal)
  broker demo                 localhost fake vault; approval page in the browser (not your vault)
  broker unlock               unlock bw in a running broker (e.g. docker exec -it broker broker unlock)
  broker unlock-approvals     clear the wrong-password lockout
  broker status               show the running broker's state
  broker doctor               check Tailscale, ntfy, files, and listeners
  broker version

Agents call the agent HTTP API with a bearer token. Administration (agents, ntfy,
bind address, approval password, authenticator, auto rules) is the loopback admin
panel only.

Config: $BROKER_CONFIG or /etc/bw2fabroker/config.toml
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "broker:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest)
	case "passwd", "ntfy", "net", "agent", "auto", "admin-token", "2fa":
		return errors.New("that command was removed; use the loopback admin panel")
	case "start":
		return cmdStart(rest)
	case "demo":
		return cmdDemo(rest)
	case "unlock":
		return cmdUnlock()
	case "login":
		return cmdLogin(rest)
	case "unlock-approvals":
		return adminSimple(adminRequest{Cmd: "unlock-approvals"})
	case "status":
		return adminSimple(adminRequest{Cmd: "status"})
	case "doctor":
		return cmdDoctor()
	case "version", "--version":
		fmt.Println("broker", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (run `broker help`)", cmd)
}

// readSecret reads a secret from the terminal without echo.
func readSecret(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("a terminal is needed to type this (use `docker exec -it` or a real terminal)")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func newApprovalPassword() (string, error) {
	pw, err := readSecret("New approval password (not your Bitwarden master password): ")
	if err != nil {
		return "", err
	}
	if len([]rune(pw)) < auth.MinPasswordLen {
		return "", fmt.Errorf("approval password must have at least %d characters", auth.MinPasswordLen)
	}
	again, err := readSecret("Repeat: ")
	if err != nil {
		return "", err
	}
	if again != pw {
		return "", errors.New("the passwords do not match")
	}
	return auth.HashPassword(pw)
}

func loadConfig() (*config.Config, string, error) {
	p := config.Path()
	c, err := config.Load(p)
	if err != nil {
		return nil, p, fmt.Errorf("%w (run `broker init` first?)", err)
	}
	return c, p, nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	domain := fs.String("ntfy-domain", "", "your self-hosted ntfy domain, e.g. ntfy.example.com")
	force := fs.Bool("force", false, "overwrite an existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := config.Path()
	if config.Exists(p) && !*force {
		return fmt.Errorf("%s already exists (use --force to replace it)", p)
	}
	if *domain != "" {
		if err := notify.CheckOwnDomain(*domain); err != nil {
			return err
		}
	}
	key, err := auth.NewKey(32)
	if err != nil {
		return err
	}
	hash, err := newApprovalPassword()
	if err != nil {
		return err
	}
	c := &config.Config{HMACKey: key, ApprovalPassword: hash}
	if *domain != "" {
		c.Ntfy = config.Ntfy{OwnDomain: *domain}
	}
	c.Defaults()
	token, adminHash, err := auth.NewAgentToken()
	if err != nil {
		return err
	}
	c.Admin.Server = "127.0.0.1:8788"
	c.Admin.TokenSHA256 = adminHash
	if err := config.Save(p, c); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (mode 0600).\nAdmin panel: http://127.0.0.1:8788/admin\nAdmin token (shown once):\n%s\n", p, token)
	if *domain == "" {
		fmt.Println("No ntfy domain given: the broker runs without notifications, and approval links go to the log and the admin panel. Set ntfy in that panel when you have a server.")
	} else {
		fmt.Println("Set ntfy url, topic, and bearer token in that panel, and add agents there.")
	}
	return nil
}

// cmdLogin logs the agents account into the broker's own bw profile. The profile is what carries
// the login, so this must run as the broker (in Docker: docker exec -it). A session from another
// machine or profile cannot stand in for it.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	email := fs.String("email", "", "log in with an email and the master password instead of an API key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path())
	if err != nil {
		return err
	}
	bw := vault.NewBW(cfg.Vault.BWPath, cfg.Vault.AppData)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if cfg.Vault.Server != "" {
		if err := bw.SetServer(ctx, cfg.Vault.Server); err != nil {
			return err
		}
	}
	id, secret := os.Getenv("BW_CLIENTID"), os.Getenv("BW_CLIENTSECRET")
	if *email == "" && (id == "" || secret == "") {
		if id, err = readSecret("client_id (user.<uuid>): "); err != nil {
			return err
		}
		if secret, err = readSecret("client_secret: "); err != nil {
			return err
		}
	}
	if err := bw.Login(ctx, *email == "", id, secret, *email); err != nil {
		return err
	}
	fmt.Println("Logged in. Next: `broker unlock` with this account's master password.")
	return nil
}

func cmdUnlock() error {
	pw, err := readSecret("Bitwarden master password of the agents account: ")
	if err != nil {
		return err
	}
	return adminSimple(adminRequest{Cmd: "unlock", Password: pw})
}
