package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/tailscale"
)

// Health is one dependency row. The lamp is always paired with a word, so the state is
// readable without relying on colour.
type Health struct {
	Name   string // "Vault"
	Detail string // one plain line
	State  string // "ok", "warn" or "bad"
	Value  string // the short word next to the lamp
	Test   string // the test action, empty when there is nothing to test
}

// ntfyState remembers the last push so the panel can show it.
type ntfyState struct {
	OK    bool
	At    time.Time
	Err   string
	Title string
}

// Health returns one row per dependency, in the order an operator reads them.
func (s *Server) Health(ctx context.Context) []Health {
	cfg := s.Config()
	rows := make([]Health, 0, 5)

	vault := Health{Name: "Vault", Detail: "The agents account. Only the broker holds it.", Test: "vault"}
	switch {
	case !s.Vault.Unlocked():
		vault.State, vault.Value = "warn", "Locked"
		vault.Detail = "Locked. Unlock it here or run `broker unlock` on the host."
	default:
		vault.State, vault.Value = "ok", "Unlocked"
	}
	if st, err := bwStatus(ctx, s.Vault); err == nil && st == "unauthenticated" {
		vault.State, vault.Value = "bad", "Not logged in"
		vault.Detail = "bw is not logged in. Run `bw login --apikey` as the broker user, with the agents account."
	}
	rows = append(rows, vault)

	push := Health{Name: "Notifications", Detail: "Where the approval request lands on your phone."}
	switch {
	case s.Notifier == nil:
		push.State, push.Value = "bad", "Not set"
		push.Detail = "No ntfy server is configured. Set the URL, domain and topic below."
	case cfg.Ntfy.URL == "" || cfg.Ntfy.Topic == "":
		push.State, push.Value = "bad", "Not set"
		push.Detail = "The ntfy URL or topic is empty. Set both below."
	default:
		push.State, push.Value = "ok", "Ready"
		push.Detail = cfg.Ntfy.URL + " · topic " + cfg.Ntfy.Topic
		if last := s.ntfyLast.Load(); last != nil {
			if last.OK {
				push.Detail += " · last push " + ago(last.At)
			} else {
				push.State, push.Value = "bad", "Failed"
				push.Detail += " · last push failed: " + last.Err
			}
		}
	}
	push.Test = "ntfy"
	rows = append(rows, push)

	ts := Health{Name: "Tailscale", Detail: "The private network the phone and the agents use."}
	switch {
	case s.Tailscale == nil:
		ts.State, ts.Value = "warn", "Not checked"
		ts.Detail = "No Tailscale checker is configured."
	default:
		st, err := s.Tailscale.Status(ctx)
		switch {
		case err != nil:
			ts.State, ts.Value = "bad", "Not running"
			ts.Detail = err.Error()
		case st.BackendState != "Running":
			ts.State, ts.Value = "warn", "Not connected"
			ts.Detail = "tailscaled is " + st.BackendState + ". Run `tailscale up`."
		default:
			ts.State, ts.Value = "ok", "Connected"
			if ip, ok := st.IPv4(); ok {
				ts.Detail = "This node is " + ip.String() + "."
			} else {
				ts.Detail = "This node has no tailnet IPv4 address."
			}
			if st.DNSName != "" {
				ts.Detail += " " + st.DNSName + "."
			}
		}
	}
	ts.Test = "tailscale"
	rows = append(rows, ts)

	page := Health{Name: "Approval page", Detail: "Where your phone opens the request."}
	if s.ApproverUp() {
		page.State, page.Value = "ok", "Up"
		page.Detail = s.ApproverBase()
		if mode := s.BindMode(); mode != "" {
			page.Detail += " · " + mode
		}
	} else {
		page.State, page.Value = "bad", "Down"
		page.Detail = "The approval listener is not up. Without it no request can be approved."
	}
	rows = append(rows, page)

	agent := Health{Name: "Agent API", Detail: "Where agents send their requests."}
	if cfg.Agent.Listen == "" {
		agent.State, agent.Value = "bad", "Not set"
		agent.Detail = "No agent listen address is set."
	} else {
		agent.State, agent.Value = "ok", "Listening"
		agent.Detail = cfg.Agent.Listen + " · " + itoa(len(cfg.Agents)) + " agent(s) registered"
		if strings.HasPrefix(cfg.Agent.Listen, "unix:") {
			agent.Detail += " · local socket only"
		}
	}
	rows = append(rows, agent)

	return rows
}

// Test runs one dependency check on demand and returns the line to show.
func (s *Server) Test(ctx context.Context, what string) (string, string) {
	cfg := s.Config()
	switch what {
	case "ntfy":
		if s.Notifier == nil {
			return "bad", "There is no ntfy server to test."
		}
		msg := notify.Message{
			Title:    "bw2fabroker test",
			Body:     "This is a test notification from the broker admin panel. Nothing is waiting for your approval.",
			Priority: 4,
			Tags:     []string{"white_check_mark"},
		}
		if err := s.Notifier.Send(ctx, msg); err != nil {
			s.noteNtfy(false, msg.Title, err)
			return "bad", "The test push failed: " + err.Error()
		}
		s.noteNtfy(true, msg.Title, nil)
		return "ok", "Test notification sent to " + cfg.Ntfy.Topic + "."
	case "tailscale":
		if s.Tailscale == nil {
			return "bad", "There is no Tailscale checker to test."
		}
		st, err := tailscale.Preflight(ctx, s.Tailscale)
		if err != nil {
			return "bad", "Tailscale is not ready: " + err.Error()
		}
		ip, _ := st.IPv4()
		return "ok", "Tailscale is running. This node is " + ip.String() + "."
	case "vault":
		st, err := bwStatus(ctx, s.Vault)
		if err != nil {
			return "bad", "The vault did not answer: " + err.Error()
		}
		switch st {
		case "unauthenticated":
			return "bad", "bw is not logged in. Run `bw login --apikey` as the broker user, with the agents account."
		case "locked":
			return "warn", "bw is logged in but locked. Unlock it here or run `broker unlock`."
		default:
			return "ok", "The vault is logged in and unlocked."
		}
	}
	return "bad", "Unknown check."
}

// ApproverBase returns the base URL of the approval page, or "" when it is down.
func (s *Server) ApproverBase() string {
	b, _ := s.linkBase.Load().(string)
	return b
}

// noteNtfy records the result of the last push.
func (s *Server) noteNtfy(ok bool, title string, err error) {
	st := &ntfyState{OK: ok, At: s.Now(), Title: title}
	if err != nil {
		st.Err = err.Error()
	}
	s.ntfyLast.Store(st)
}

// bwStatus asks the vault for the bw status, when the vault can answer it.
func bwStatus(ctx context.Context, v interface{ Unlocked() bool }) (string, error) {
	type stater interface {
		Status(ctx context.Context) (string, error)
	}
	s, ok := v.(stater)
	if !ok {
		return "", fmt.Errorf("this vault cannot report its status")
	}
	return s.Status(ctx)
}

// ago renders how long ago something happened.
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " min ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + " h ago"
	default:
		return itoa(int(d.Hours()/24)) + " d ago"
	}
}

// itoa renders a small number.
func itoa(n int) string { return fmt.Sprintf("%d", n) }
