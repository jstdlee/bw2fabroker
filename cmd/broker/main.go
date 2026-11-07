// Command broker is the bw2fabroker server and its admin CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

var version = "dev"

const usage = `broker: Bitwarden access broker with phone approval

Setup:
  broker init [--ntfy-domain ntfy.example.com]   create config, HMAC key, approval password
  broker passwd                                  change the approval password
  broker ntfy set --url URL --topic T [--token K] set the ntfy target (own domain only); sends a test
  broker net set [--ip IP] [--port N] [--public-host H] [--agent-listen L] [--agent-socket-gid G]
  broker agent add|rm|resume NAME, broker agent list
  broker auto add ITEM_ID [--field F], broker auto rm ITEM_ID [--field F], broker auto list

Run:
  broker start                start serving (asks for the bw master password on a terminal)
  broker unlock               unlock bw in a running broker (e.g. docker exec -it broker broker unlock)
  broker unlock-approvals     clear the wrong-password lockout
  broker status               show the running broker's state
  broker doctor               check Tailscale, ntfy, files, and listeners
  broker version

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
	case "passwd":
		return cmdPasswd()
	case "ntfy":
		return cmdNtfy(rest)
	case "net":
		return cmdNet(rest)
	case "agent":
		return cmdAgent(rest)
	case "auto":
		return cmdAuto(rest)
	case "start":
		return cmdStart(rest)
	case "unlock":
		return cmdUnlock()
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

func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
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
	if *domain == "" {
		d, err := readLine("Your self-hosted ntfy domain (e.g. ntfy.example.com): ")
		if err != nil {
			return err
		}
		*domain = d
	}
	if err := notify.CheckOwnDomain(*domain); err != nil {
		return err
	}
	key, err := auth.NewKey(32)
	if err != nil {
		return err
	}
	hash, err := newApprovalPassword()
	if err != nil {
		return err
	}
	c := &config.Config{HMACKey: key, ApprovalPassword: hash, Ntfy: config.Ntfy{OwnDomain: *domain}}
	c.Defaults()
	if err := config.Save(p, c); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (mode 0600).\nNext: broker ntfy set --url https://%s --topic <topic> --token <token>\n      broker agent add <name>\n", p, *domain)
	return nil
}

func cmdPasswd() error {
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	hash, err := newApprovalPassword()
	if err != nil {
		return err
	}
	c.ApprovalPassword = hash
	if err := config.Save(p, c); err != nil {
		return err
	}
	fmt.Println("Approval password changed. A running broker picks it up at once.")
	return nil
}

func cmdNtfy(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("usage: broker ntfy set --url URL --topic T [--token K]")
	}
	fs := flag.NewFlagSet("ntfy set", flag.ContinueOnError)
	u := fs.String("url", "", "https://<own domain>")
	topic := fs.String("topic", "", "topic")
	token := fs.String("token", "", "ntfy access token (optional)")
	noTest := fs.Bool("no-test", false, "do not send a test message")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	n, err := notify.New(*u, c.Ntfy.OwnDomain, *topic, *token)
	if err != nil {
		return err
	}
	if !*noTest {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := n.Send(ctx, notify.Message{Title: "bw2fabroker", Body: "Test message: ntfy is set up.", Priority: 3}); err != nil {
			return fmt.Errorf("test message failed, config not saved: %w", err)
		}
		fmt.Println("Test message sent.")
	}
	c.Ntfy.URL, c.Ntfy.Topic, c.Ntfy.Token = *u, *topic, *token
	return config.Save(p, c)
}

func cmdNet(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("usage: broker net set [--ip IP] [--port N] [--public-host H] [--agent-listen L]")
	}
	fs := flag.NewFlagSet("net set", flag.ContinueOnError)
	ip := fs.String("ip", "-", "approver bind IP (a tailnet IP of this node; empty = automatic)")
	port := fs.Int("port", 0, "approver port")
	host := fs.String("public-host", "-", "host used in approval links (e.g. MagicDNS name; empty = IP)")
	listen := fs.String("agent-listen", "", "agent API: unix:/path, 127.0.0.1:PORT, or 100.x.y.z:PORT")
	gid := fs.Int("agent-socket-gid", -1, "group id allowed to use the agent unix socket (0 = group broker-clients if present)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	if *ip != "-" {
		c.Approver.BindIP = *ip
	}
	if *port != 0 {
		c.Approver.Port = *port
	}
	if *host != "-" {
		c.Approver.PublicHost = *host
	}
	if *listen != "" {
		c.Agent.Listen = *listen
	}
	if *gid >= 0 {
		c.Agent.SocketGID = *gid
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := config.Save(p, c); err != nil {
		return err
	}
	fmt.Println("Saved. Restart the broker to apply listener changes.")
	return nil
}

var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func cmdAgent(args []string) error {
	if len(args) == 1 && args[0] == "list" {
		c, _, err := loadConfig()
		if err != nil {
			return err
		}
		for _, n := range c.AgentNames() {
			fmt.Printf("%s\tcreated %s\n", n, c.Agents[n].Created.Format(time.RFC3339))
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: broker agent add|rm|resume NAME, or broker agent list")
	}
	name := args[1]
	if !agentNameRe.MatchString(name) {
		return errors.New("agent name: 1-32 characters of a-z 0-9 _ -, starting with a letter or digit")
	}
	switch args[0] {
	case "add":
		c, p, err := loadConfig()
		if err != nil {
			return err
		}
		if _, ok := c.Agents[name]; ok {
			return fmt.Errorf("agent %q exists; `broker agent rm %s` first to replace its token", name, name)
		}
		tok, hash, err := auth.NewAgentToken()
		if err != nil {
			return err
		}
		c.Agents[name] = config.Agent{TokenSHA256: hash, Created: time.Now().UTC().Truncate(time.Second)}
		if err := config.Save(p, c); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Token for agent %q (shown once; only its hash is stored):\n", name)
		fmt.Println(tok)
		return nil
	case "rm":
		c, p, err := loadConfig()
		if err != nil {
			return err
		}
		if _, ok := c.Agents[name]; !ok {
			return fmt.Errorf("no agent %q", name)
		}
		delete(c.Agents, name)
		return config.Save(p, c)
	case "resume":
		return adminSimple(adminRequest{Cmd: "resume", Agent: name})
	}
	return errors.New("usage: broker agent add|rm|resume NAME")
}

func cmdAuto(args []string) error {
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "list" {
		for _, r := range c.Auto {
			f := r.Field
			if f == "" {
				f = "(any field except totp)"
			}
			fmt.Printf("%s\t%s\n", r.ItemID, f)
		}
		return nil
	}
	if len(args) < 2 {
		return errors.New("usage: broker auto add|rm ITEM_ID [--field F], or broker auto list")
	}
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	field := fs.String("field", "", "one field (default: any field except totp)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	id := args[1]
	if !vault.IsID(id) {
		return errors.New("auto rules take an item id (a UUID), not a name")
	}
	if *field != "" {
		f, ok := contract.ParseField(*field)
		if !ok {
			return fmt.Errorf("field %q is not allowed", *field)
		}
		if f.Kind == "totp" {
			return errors.New("totp can never be auto: a TOTP code is a second factor")
		}
	}
	switch args[0] {
	case "add":
		for _, r := range c.Auto {
			if r.ItemID == id && r.Field == *field {
				return nil
			}
		}
		c.Auto = append(c.Auto, config.AutoRule{ItemID: id, Field: *field})
	case "rm":
		out := c.Auto[:0]
		for _, r := range c.Auto {
			if !(r.ItemID == id && r.Field == *field) {
				out = append(out, r)
			}
		}
		c.Auto = out
	default:
		return errors.New("usage: broker auto add|rm ITEM_ID [--field F]")
	}
	return config.Save(p, c)
}

func cmdUnlock() error {
	pw, err := readSecret("Bitwarden master password of the agents account: ")
	if err != nil {
		return err
	}
	return adminSimple(adminRequest{Cmd: "unlock", Password: pw})
}
