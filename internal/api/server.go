// Package api serves the two listeners: the agent API (/v1, contract only) and the approver pages
// (/a, tailnet only). The two route sets never share a listener.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/audit"
	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/pending"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// Limits.
const (
	DefaultExpiry        = 120 * time.Second
	DefaultHold          = 50 * time.Second
	MaxPasswordErrors    = 3
	GlobalPasswordErrors = 10
	GlobalPasswordWindow = time.Hour
	SuspendDenials       = 3
	SuspendWindow        = 10 * time.Minute
	RequestRate          = 20 // new requests per agent per RequestRateWindow
	RequestRateWindow    = 10 * time.Minute
)

// Server holds broker state. It keeps no database.
type Server struct {
	Config   func() *config.Config
	Vault    vault.Vault
	Notifier notify.Notifier
	Linker   *auth.Linker
	Store    *pending.Store
	Log      *slog.Logger
	Now      func() time.Time
	Expiry   time.Duration
	Hold     time.Duration

	// AllowLoopback lets 127.0.0.1 and ::1 open the approval page. Only `broker demo`
	AllowLoopback bool

	// UpdateConfig saves a mutated config. The admin panel uses it.
	UpdateConfig func(func(*config.Config) error) error
	// Audit is the on-disk decision log. Nil in tests that do not set it.
	Audit *audit.Log

	allowLAN atomic.Bool
	bindMode atomic.Value

	linkBase        atomic.Value // string, e.g. http://100.x.y.z:8787; empty when the approver side is down
	approvalMu      sync.Mutex
	pwFailures      []time.Time
	approvalsLocked bool

	agentMu   sync.Mutex
	denials   map[string][]time.Time
	requests  map[string][]time.Time
	suspended map[string]bool
}

// New builds a server.
func New(cfg func() *config.Config, v vault.Vault, n notify.Notifier, l *auth.Linker, log *slog.Logger) *Server {
	s := &Server{Config: cfg, Vault: v, Notifier: n, Linker: l, Log: log, Now: time.Now,
		Expiry: DefaultExpiry, Hold: DefaultHold,
		denials: map[string][]time.Time{}, requests: map[string][]time.Time{}, suspended: map[string]bool{}}
	s.linkBase.Store("")
	s.bindMode.Store("")
	s.Store = pending.New(func() time.Time { return s.Now() }, func(r *pending.Request) {
		s.audit("expired", r.Agent, slog.String("request_id", r.ID), slog.String("item_id", r.Item.ID), slog.String("field", r.Field.String()))
	})
	return s
}

func (s *Server) audit(event, agent string, attrs ...slog.Attr) {
	args := []any{slog.String("event", event)}
	if agent != "" {
		args = append(args, slog.String("agent", agent))
	}
	ev := audit.Event{Time: s.Now(), Actor: agent, Result: event}
	var item, field string
	for _, a := range attrs {
		args = append(args, a)
		switch a.Key {
		case "remote":
			ev.IP = a.Value.String()
		case "name":
			ev.Name = a.Value.String()
		case "item_id":
			item = a.Value.String()
		case "field":
			field = a.Value.String()
		}
	}
	s.Log.Info("audit", args...)
	if ev.Name == "" && (item != "" || field != "") {
		ev.Name = item + "/" + field
	}
	if ev.Name == "" {
		ev.Name = event
	}
	if s.Audit != nil {
		s.Audit.Add(ev)
	}
}

// SetExposure records whether the approver is on Tailscale or a LAN address.
func (s *Server) SetExposure(mode string) {
	s.allowLAN.Store(mode == "lan")
	s.bindMode.Store(mode)
}

// BindMode is "tailscale", "lan", or "".
func (s *Server) BindMode() string {
	m, _ := s.bindMode.Load().(string)
	return m
}

// SetApproverBase sets the link base when the approver listener is up, or "" when it is down.
// Going down ends every pending request as expired.
func (s *Server) SetApproverBase(base string) {
	old, _ := s.linkBase.Load().(string)
	s.linkBase.Store(base)
	if base == "" && old != "" {
		for _, r := range s.Store.CancelAll(contract.CodeExpired) {
			s.audit("expired", r.Agent, slog.String("request_id", r.ID), slog.String("cause", "approver listener down"))
		}
	}
}

// ApproverUp reports whether approval links can be served.
func (s *Server) ApproverUp() bool { b, _ := s.linkBase.Load().(string); return b != "" }

// UnlockVault unlocks bw with the master password (admin socket only).
func (s *Server) UnlockVault(ctx context.Context, master string) error {
	err := s.Vault.Unlock(ctx, master)
	if err != nil {
		s.audit("vault_unlock_failed", "")
		return err
	}
	s.audit("vault_unlocked", "")
	return nil
}

// ClearApprovalLock ends the global password lockout.
func (s *Server) ClearApprovalLock() {
	s.approvalMu.Lock()
	s.approvalsLocked = false
	s.pwFailures = nil
	s.approvalMu.Unlock()
	s.audit("approvals_unlocked", "")
}

// ApprovalsLocked reports the global password lockout.
func (s *Server) ApprovalsLocked() bool {
	s.approvalMu.Lock()
	defer s.approvalMu.Unlock()
	return s.approvalsLocked
}

// Resume un-suspends an agent.
func (s *Server) Resume(agent string) {
	s.agentMu.Lock()
	delete(s.suspended, agent)
	delete(s.denials, agent)
	s.agentMu.Unlock()
	s.audit("agent_resumed", agent)
}

// Suspended reports whether an agent is suspended.
func (s *Server) Suspended(agent string) bool {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	return s.suspended[agent]
}

func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) recordDenial(agent string) {
	now := s.Now()
	s.agentMu.Lock()
	s.denials[agent] = append(prune(s.denials[agent], now, SuspendWindow), now)
	suspend := len(s.denials[agent]) >= SuspendDenials && !s.suspended[agent]
	if suspend {
		s.suspended[agent] = true
	}
	s.agentMu.Unlock()
	if suspend {
		s.audit("agent_suspended", agent)
		s.push(notify.Message{Title: "Agent suspended", Body: "Agent " + agent + " was denied 3 times in 10 minutes. Resume it from the admin panel.", Priority: 4, Tags: []string{"warning"}})
	}
}

func (s *Server) allowRequest(agent string) bool {
	now := s.Now()
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	s.requests[agent] = prune(s.requests[agent], now, RequestRateWindow)
	if len(s.requests[agent]) >= RequestRate {
		return false
	}
	s.requests[agent] = append(s.requests[agent], now)
	return true
}

// push sends a best-effort informational message.
func (s *Server) push(m notify.Message) {
	if s.Notifier == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.Notifier.Send(ctx, m); err != nil {
			s.Log.Warn("ntfy send failed", slog.String("error", err.Error()))
		}
	}()
}

// ---------------------------------------------------------------- agent API

// AgentHandler serves /v1 only. Every response goes through contract.Write.
func (s *Server) AgentHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic in agent handler", slog.Any("panic", rec))
				contract.Write(w, contract.Rejected("", contract.CodeInternalError))
			}
		}()
		s.serveAgent(w, r)
	})
}

func (s *Server) agentFromToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" || len(tok) > 200 {
		return "", false
	}
	cfg := s.Config()
	if cfg.Admin.TokenSHA256 != "" && auth.TokenMatches(tok, cfg.Admin.TokenSHA256) {
		return "", false
	}
	found := ""
	for _, name := range cfg.AgentNames() {
		if auth.TokenMatches(tok, cfg.Agents[name].TokenSHA256) {
			found = name
		}
	}
	return found, found != ""
}

func (s *Server) serveAgent(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromToken(r)
	if !ok {
		s.audit("unauthorized", "", slog.String("remote", r.RemoteAddr))
		contract.Write(w, contract.Rejected("", contract.CodeUnauthorized))
		return
	}
	if r.URL.RawQuery != "" && !(r.Method == http.MethodGet && r.URL.Path == "/v1/search" && len(r.URL.Query()) == 1 && r.URL.Query().Get("q") != "") {
		contract.Write(w, contract.Rejected("", contract.CodeBadRequest))
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
		contract.Write(w, s.create(r.Context(), agent, r))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/requests/") && strings.HasSuffix(r.URL.Path, "/wait"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/requests/"), "/wait")
		if !contract.ValidRequestID(id) || r.ContentLength > 0 {
			contract.Write(w, contract.Rejected("", contract.CodeBadRequest))
			return
		}
		resp := s.Store.Wait(r.Context(), id, agent, s.Hold)
		if resp.Status == contract.StatusApproved {
			s.audit("delivered", agent, slog.String("request_id", id))
		}
		contract.Write(w, resp)
	case r.Method == http.MethodGet && (r.URL.Path == "/v1/items" || r.URL.Path == "/v1/search"):
		s.serveCatalog(w, r, agent)
	default:
		contract.Write(w, contract.Rejected("", contract.CodeBadRequest))
	}
}

func (s *Server) create(ctx context.Context, agent string, r *http.Request) contract.Response {
	if s.Suspended(agent) {
		return contract.Rejected("", contract.CodeSuspended)
	}
	req, code := contract.ParseRequest(r.Body)
	if code != "" {
		s.audit("rejected", agent, slog.String("code", string(code)))
		return contract.Rejected("", code)
	}
	field, _ := contract.ParseField(req.Field)
	if !s.allowRequest(agent) {
		s.audit("rejected", agent, slog.String("code", string(contract.CodeRateLimited)))
		return contract.Rejected("", contract.CodeRateLimited)
	}
	if !s.Vault.Unlocked() {
		s.audit("rejected", agent, slog.String("code", "locked"), slog.String("cause", "vault locked"))
		return contract.Rejected("", contract.CodeLocked)
	}
	item, err := s.Vault.Resolve(ctx, req.Item)
	if code := vaultCode(err); code != "" {
		s.logVaultErr(agent, err, code)
		return contract.Rejected("", code)
	}
	if err := s.Vault.HasField(ctx, item.ID, field); err != nil {
		code := vaultCode(err)
		if errors.Is(err, vault.ErrNoField) {
			code = contract.CodeFieldNotAllowed
		}
		s.logVaultErr(agent, err, code)
		return contract.Rejected("", code)
	}
	id, err := auth.NewRequestID()
	if err != nil {
		return contract.Rejected("", contract.CodeInternalError)
	}
	base := []slog.Attr{slog.String("request_id", id), slog.String("item_id", item.ID), slog.String("field", field.String()), slog.String("reason", req.Reason)}
	s.audit("request", agent, base...)

	cfg := s.Config()
	if cfg.IsAuto(item.ID, field.String()) {
		value, err := s.Vault.Read(ctx, item.ID, field)
		if code := vaultCode(err); code != "" {
			s.logVaultErr(agent, err, code)
			return contract.Rejected(id, code)
		}
		if contract.ValidValue(value) != nil {
			s.audit("rejected", agent, append(base, slog.String("code", "value_too_large"))...)
			return contract.Rejected(id, contract.CodeValueTooLarge)
		}
		s.audit("delivered", agent, append(base, slog.String("code", "auto"))...)
		s.push(notify.Message{Title: "Auto: " + agent + " read a secret", Body: agent + " read " + item.Name + " / " + field.String() + " (auto rule).", Priority: 2})
		return contract.Approved(id, value, contract.CodeAuto)
	}

	if s.ApprovalsLocked() || !s.ApproverUp() || s.Notifier == nil {
		s.audit("rejected", agent, append(base, slog.String("code", "locked"))...)
		return contract.Rejected(id, contract.CodeLocked)
	}
	now := s.Now()
	pr := &pending.Request{ID: id, Agent: agent, Item: item, Field: field, Reason: req.Reason, Created: now, Expires: now.Add(s.Expiry)}
	if err := s.Store.Add(pr); err != nil {
		s.audit("rejected", agent, append(base, slog.String("code", "rate_limited"))...)
		return contract.Rejected("", contract.CodeRateLimited)
	}
	linkBase, _ := s.linkBase.Load().(string)
	link := linkBase + "/a/" + s.Linker.Sign(id, pr.Expires)
	nctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = s.Notifier.Send(nctx, notify.Message{
		Title:    "Approve secret for " + agent,
		Body:     agent + " wants " + item.Name + " / " + field.String() + ". Expires in " + s.Expiry.String() + ".",
		Click:    link,
		Priority: 5,
		Tags:     []string{"key"},
		Actions:  []notify.Action{{Action: "view", Label: "Approve", URL: link}},
	})
	if err != nil {
		s.Store.Remove(id)
		s.Log.Warn("ntfy send failed", slog.String("error", err.Error()))
		s.audit("rejected", agent, append(base, slog.String("code", "locked"), slog.String("cause", "notify failed"))...)
		return contract.Rejected(id, contract.CodeLocked)
	}
	s.audit("notified", agent, slog.String("request_id", id))
	return contract.Pending(id)
}

func vaultCode(err error) contract.Code {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, vault.ErrUnknownItem):
		return contract.CodeUnknownItem
	case errors.Is(err, vault.ErrAmbiguousItem):
		return contract.CodeAmbiguousItem
	case errors.Is(err, vault.ErrNoField):
		return contract.CodeFieldNotAllowed
	case errors.Is(err, vault.ErrLocked):
		return contract.CodeLocked
	}
	return contract.CodeInternalError
}

func (s *Server) logVaultErr(agent string, err error, code contract.Code) {
	if code == contract.CodeInternalError {
		s.Log.Error("vault error", slog.String("error", err.Error()))
	}
	s.audit("rejected", agent, slog.String("code", string(code)))
}

// ---------------------------------------------------------------- approver helpers

// remoteIsTailnet reports whether the caller's address is in Tailscale's ranges. This is a range
// check only; which tailnet device calls is not checked (owner decision).
func remoteIsTailnet(r *http.Request) bool {
	ip, ok := remoteIP(r)
	return ok && config.IsTailnetIP(ip)
}

func remoteIsLoopback(r *http.Request) bool {
	ip, ok := remoteIP(r)
	return ok && ip.IsLoopback()
}

func remoteIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

func (s *Server) callerMayApprove(r *http.Request) bool {
	ip, ok := remoteIP(r)
	if !ok {
		return false
	}
	if config.IsTailnetIP(ip) {
		return true
	}
	if s.AllowLoopback && ip.IsLoopback() {
		return true
	}
	return s.allowLAN.Load() && ip.IsPrivate()
}

func (s *Server) wrongPassword(id, agent string) (denied bool) {
	n := s.Store.PasswordError(id)
	now := s.Now()
	s.approvalMu.Lock()
	s.pwFailures = append(prune(s.pwFailures, now, GlobalPasswordWindow), now)
	lockAll := len(s.pwFailures) >= GlobalPasswordErrors && !s.approvalsLocked
	if lockAll {
		s.approvalsLocked = true
	}
	s.approvalMu.Unlock()
	s.audit("wrong_password", agent, slog.String("request_id", id), slog.Int("count", n))
	if lockAll {
		s.audit("approvals_locked", "")
		for _, r := range s.Store.CancelAll(contract.CodeTooManyPasswordErrors) {
			s.audit("denied", r.Agent, slog.String("request_id", r.ID), slog.String("code", "too_many_password_errors"))
		}
		s.push(notify.Message{Title: "Approvals locked", Body: "10 wrong approval passwords in an hour. Run `broker unlock-approvals` to allow approvals again.", Priority: 5, Tags: []string{"rotating_light"}})
	}
	if n >= MaxPasswordErrors {
		if _, err := s.Store.Finish(id, contract.Denied(id, contract.CodeTooManyPasswordErrors)); err == nil {
			s.audit("denied", agent, slog.String("request_id", id), slog.String("code", "too_many_password_errors"))
			s.recordDenial(agent)
			return true
		}
	}
	return lockAll
}
