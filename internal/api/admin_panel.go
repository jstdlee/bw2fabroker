package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/notify"
)

var adminPage = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>bw2fabroker admin</title>
<style>` + designCSS + `</style></head><body><main>
<div class="tabs">
<a href="/">Overview</a><a href="/agent">Agents</a><a href="/mcp">MCP</a><a href="/api">API</a><a class="on" href="/admin">Admin</a>
</div>
{{if .Login}}
<h1>bw2fabroker</h1>
<p class="lead">This page is only on this machine. Agents do not use it.</p>
{{if .Notice}}<p class="notice bad">{{.Notice}}</p>{{end}}
<div class="card"><div class="row stack">
<form method="post" action="/admin/login">
<div class="t">Admin token</div>
<div class="d">The key from <code>broker init</code> or the credential file.</div>
<div class="f" style="margin-top:8px"><input name="token" type="password" autocomplete="current-password" required><button class="primary" type="submit">Enter</button></div>
</form>
</div></div>
{{else}}
<h1>bw2fabroker</h1>
<p class="lead">Admin panel. Loopback only. An agent calls the HTTP API with its own token and cannot open this page.</p>
{{if .Notice}}<p class="notice {{.NoticeKind}}">{{.Notice}}</p>{{end}}
{{if .Secret}}<p class="notice ok">Shown once. Copy it now; it is not stored in this page.<br><span class="secret">{{.Secret}}</span></p>{{end}}

<h2>Status</h2>
<div class="card">
{{range .Health}}
<div class="row">
<div class="grow"><div class="t">{{.Name}}</div><div class="d">{{.Detail}}</div></div>
<div class="c"><span class="lamp {{.State}}"></span><span class="state {{.State}}">{{.Value}}</span>
{{if .Test}}<form class="inline" method="post" action="/admin/test/{{.Test}}"><button class="quiet" type="submit">Test</button></form>{{end}}
</div>
</div>
{{end}}
{{if not .Unlocked}}
<div class="row stack">
<div class="t">Unlock the vault</div>
<div class="d">The master password of the agents account. It is used once and never written down.</div>
<form class="f" method="post" action="/admin/unlock">
<input name="password" type="password" placeholder="Bitwarden master password" autocomplete="off" required>
<button class="primary" type="submit">Unlock</button>
</form>
</div>
{{end}}
</div>

<h2>Bitwarden</h2>
<div class="card">
<div class="row">
<div class="grow"><div class="t">Server</div><div class="d">Bitwarden cloud, Vaultwarden, or your own self-hosted server. Saving this runs <code>bw config server</code>. Startup does it again.</div></div>
<div class="c"><form class="f" method="post" action="/admin/vault">
<input name="server" value="{{.VaultServer}}" placeholder="https://vault.example.com" autocomplete="off">
<button class="primary" type="submit">Save</button></form></div>
</div>
<div class="row stack">
<div class="t">Approval password</div>
<div class="d">The password you type on the phone. Not the Bitwarden master password.</div>
<form class="f" method="post" action="/admin/password">
<input name="password" type="password" placeholder="New password" autocomplete="new-password" required>
<input name="again" type="password" placeholder="Repeat" autocomplete="new-password" required>
<button class="primary" type="submit">Change</button></form>
</div>
</div>

<h2>Addresses</h2>
<div class="card">
<div class="row">
<div class="grow"><div class="t">Phone page</div><div class="d">A tailnet address or one private LAN address. The approval port updates within 30 seconds. The agent address needs a restart.</div></div>
</div>
<div class="row">
<div class="grow"><div class="t">Approval host</div><div class="d">The address your phone opens. A tailnet IP, or a hostname on the LAN.</div></div>
<div class="c"><form class="f" method="post" action="/admin/bind">
<input name="host" value="{{.Host}}" placeholder="100.x.y.z" autocomplete="off">
<button class="quiet" type="submit">Save</button></form></div>
</div>
<div class="row">
<div class="grow"><div class="t">Approval port</div><div class="d">The port in the approval link.</div></div>
<div class="c"><form class="f tight" method="post" action="/admin/bind">
<input name="port" value="{{.Port}}" inputmode="numeric">
<button class="quiet" type="submit">Save</button></form></div>
</div>
<div class="row">
<div class="grow"><div class="t">Name in links</div><div class="d">Optional. The host name used in the link your phone opens, such as a MagicDNS name.</div></div>
<div class="c"><form class="f" method="post" action="/admin/bind">
<input name="public_host" value="{{.Public}}" placeholder="optional" autocomplete="off">
<button class="quiet" type="submit">Save</button></form></div>
</div>
<div class="row">
<div class="grow"><div class="t">Agent API</div><div class="d">Where agents connect. This needs a restart of the broker.</div></div>
<div class="c"><form class="f" method="post" action="/admin/bind">
<input name="agent_listen" value="{{.AgentListen}}" placeholder="100.x.y.z:8786" autocomplete="off">
<button class="quiet" type="submit">Save</button></form></div>
</div>
</div>

<h2>Notifications</h2>
<div class="card">
<div class="row stack">
<div class="t">ntfy</div>
<div class="d">Your own ntfy server. The broker refuses ntfy.sh and plain http, and the topic must reject requests with no bearer token. Leave every field empty to run without notifications; approval links then appear in the log and under “Waiting”.</div>
<form class="f" method="post" action="/admin/ntfy">
<input name="url" value="{{.NtfyURL}}" placeholder="https://ntfy.example.com" autocomplete="off">
<input name="domain" value="{{.Domain}}" placeholder="ntfy.example.com" autocomplete="off">
<input name="topic" value="{{.Topic}}" placeholder="bw-approvals" autocomplete="off">
<input name="token" type="password" placeholder="unchanged" autocomplete="off">
<button class="primary" type="submit">Save notifications</button></form>
<form class="inline" method="post" action="/admin/ntfy/test"><button class="quiet" type="submit">Send a test notification</button></form>
</div>
</div>

<h2>Waiting</h2>
<div class="card">
{{if .Pending}}
{{range .Pending}}
<div class="row">
<div class="grow"><div class="t">{{.Item}} / {{.Field}}</div><div class="d">for {{.Agent}} — {{.Reason}}</div></div>
<div class="c"><span class="state">expires {{.Expires.Format "15:04:05"}}</span><a class="quiet" href="{{.Link}}">Open</a></div>
</div>
{{end}}
{{else}}
<div class="row">
<div class="grow"><div class="t">No request is waiting</div><div class="d">When nothing is configured for notifications, the links of pending requests appear here for 120 seconds.</div></div>
</div>
{{end}}
</div>

<h2>Agents</h2>
<div class="card">
{{range .Agents}}
<div class="row">
<div class="grow"><div class="t">{{.}}</div><div class="d">Bearer token for this agent. Shown once when it was added.</div></div>
<div class="c">
<form class="inline" method="post" action="/admin/agent/resume"><input type="hidden" name="name" value="{{.}}"><button class="quiet" type="submit">Resume</button></form>
<form class="inline" method="post" action="/admin/agent/remove"><input type="hidden" name="name" value="{{.}}"><button class="danger" type="submit">Remove</button></form>
</div>
</div>
{{end}}
<div class="row">
<div class="grow"><div class="t">Add an agent</div><div class="d">The token is shown once. Resume clears a suspension after three denials.</div></div>
<div class="c"><form class="f tight" method="post" action="/admin/agent/add">
<input name="name" placeholder="name" autocomplete="off" required>
<button class="primary" type="submit">Add</button></form></div>
</div>
</div>

<h2>Auto rules</h2>
<div class="card">
{{range .Rules}}
<div class="row">
<div class="grow"><div class="t"><code>{{.ItemID}}</code></div><div class="d">{{if .Field}}{{.Field}}{{else}}any field except totp{{end}}</div></div>
<div class="c"><form class="inline" method="post" action="/admin/auto/remove"><input type="hidden" name="item" value="{{.ItemID}}"><input type="hidden" name="field" value="{{.Field}}"><button class="quiet" type="submit">Remove</button></form></div>
</div>
{{end}}
<div class="row">
<div class="grow"><div class="t">Allow without asking</div><div class="d">These items are returned to the agent without a phone approval. A TOTP field is never automatic.</div></div>
<div class="c"><form class="f tight" method="post" action="/admin/auto/add">
<input name="item" placeholder="item id" required>
<input name="field" placeholder="field" autocomplete="off">
<button class="primary" type="submit">Add</button></form></div>
</div>
</div>

<h2>Authenticator</h2>
<div class="card">
{{range .TwoFA}}
<div class="row">
<div class="grow"><div class="t"><code>{{.}}</code></div><div class="d">Asks for a code before this item is approved.</div></div>
<div class="c"><form class="inline" method="post" action="/admin/2fa/remove"><input type="hidden" name="item" value="{{.}}"><button class="quiet" type="submit">Stop asking</button></form></div>
</div>
{{end}}
<div class="row">
<div class="grow"><div class="t">Enrol</div><div class="d">Replaces the secret. The old authenticator app stops working. The new address is shown once.</div></div>
<div class="c"><form class="inline" method="post" action="/admin/2fa/enroll"><button class="quiet" type="submit">Create secret</button></form></div>
</div>
<div class="row">
<div class="grow"><div class="t">Require a code</div><div class="d">The item id that asks for a code before it is approved.</div></div>
<div class="c"><form class="f tight" method="post" action="/admin/2fa/add">
<input name="item" placeholder="item id" required>
<button class="primary" type="submit">Add</button></form></div>
</div>
</div>

<h2>Vault names</h2>
<div class="card">
<div class="row">
<div class="grow"><div class="t">Search</div><div class="d">Names and field names only. This page cannot run arbitrary Bitwarden commands.</div></div>
<div class="c"><form class="f tight" method="get" action="/admin/search">
<input name="q" value="{{.Query}}" placeholder="name" autocomplete="off">
<button class="quiet" type="submit">Search</button></form></div>
</div>
{{range .Items}}
<div class="row">
<div class="grow"><div class="t">{{.Name}}{{if .Folder}} <span class="state">({{.Folder}})</span>{{end}}</div><div class="d"><code>{{.ID}}</code> · {{.Fields}}</div></div>
</div>
{{end}}
</div>

<h2>Admin token</h2>
<div class="card">
<div class="row">
<div class="grow"><div class="t">Replace the token</div><div class="d">Signs this browser in with the new one. The old token stops working.</div></div>
<div class="c"><form class="inline" method="post" action="/admin/token"><button class="danger" type="submit">Replace token</button></form></div>
</div>
</div>
<p class="foot">bw2fabroker {{.Version}} · the panel answers on loopback only</p>
{{end}}
</main>
</body></html>`))

type adminPending struct {
	Agent, Item, Field, Reason, Link string
	Expires                          time.Time
}

type adminView struct {
	Login                                                                                                   bool
	Mode, Host, Public, NtfyURL, Domain, Topic, Notice, NoticeKind, Secret, Query, AgentListen, VaultServer string
	Version                                                                                                 string
	Port                                                                                                    int
	LAN, Unlocked                                                                                           bool
	Health                                                                                                  []Health
	Agents                                                                                                  []string
	Pending                                                                                                 []adminPending
	Rules                                                                                                   []config.AutoRule
	TwoFA                                                                                                   []string
	Items                                                                                                   []adminItem
}

type adminItem struct {
	ID, Name, Folder, Fields string
}

// AdminHandler is the browser panel. A cookie set from the admin token gates it.
func (s *Server) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminFromLoopback(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/admin/login" && r.Method == http.MethodPost {
			s.adminLogin(w, r)
			return
		}
		if !s.adminAuthed(r) {
			s.adminRender(w, r, adminView{Login: true, Version: s.Version})
			return
		}
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/admin" || r.URL.Path == "/admin/" || r.URL.Path == "/admin/search"):
			s.adminHome(w, r, "", "")
		case r.Method == http.MethodPost && r.URL.Path == "/admin/test/ntfy":
			s.adminTest(w, r, "ntfy")
		case r.Method == http.MethodPost && r.URL.Path == "/admin/test/tailscale":
			s.adminTest(w, r, "tailscale")
		case r.Method == http.MethodPost && r.URL.Path == "/admin/test/vault":
			s.adminTest(w, r, "vault")
		case r.Method == http.MethodPost && r.URL.Path == "/admin/unlock":
			s.adminUnlock(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/bind":
			s.adminBind(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/ntfy":
			s.adminNtfy(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/ntfy/test":
			s.adminNtfyTest(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/agent/add":
			s.adminAgentAdd(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/agent/remove":
			s.adminAgentRemove(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/auto/add":
			s.adminAuto(w, r, true)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/auto/remove":
			s.adminAuto(w, r, false)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/2fa/add":
			s.admin2FA(w, r, true)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/2fa/remove":
			s.admin2FA(w, r, false)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/2fa/enroll":
			s.admin2FAEnroll(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/password":
			s.adminPassword(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/vault":
			s.adminVault(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/token":
			s.adminRotateToken(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/agent/resume":
			s.adminResume(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.adminTokenOK(r.PostForm.Get("token")) {
		s.adminRender(w, r, adminView{Login: true, Notice: "Wrong token.", NoticeKind: "bad", Version: s.Version})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "broker_admin", Value: strings.TrimSpace(r.PostForm.Get("token")), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminAuthed(r *http.Request) bool {
	c, err := r.Cookie("broker_admin")
	if err != nil {
		return false
	}
	return s.adminTokenOK(c.Value)
}

func (s *Server) adminTokenOK(token string) bool {
	cfg := s.Config()
	token = strings.TrimSpace(token)
	if token == "" || cfg.Admin.TokenSHA256 == "" || cfg.AgentHasHash(auth.HashToken(token)) {
		return false
	}
	return tokenMatches(cfg.Admin.TokenSHA256, token)
}

func adminFromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func tokenMatches(storedHex, token string) bool {
	h, err := hex.DecodeString(storedHex)
	if err != nil || len(h) != sha256.Size || strings.TrimSpace(token) == "" {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return subtle.ConstantTimeCompare(sum[:], h) == 1
}

func (s *Server) adminHome(w http.ResponseWriter, r *http.Request, notice, kind string) {
	cfg := s.Config()
	v := adminView{
		Mode: s.BindMode(), Host: cfg.Approver.BindHost, Public: cfg.Approver.PublicHost,
		Port: cfg.Approver.Port, NtfyURL: cfg.Ntfy.URL, Domain: cfg.Ntfy.OwnDomain, Topic: cfg.Ntfy.Topic,
		LAN: s.allowLAN.Load(), Unlocked: s.Vault.Unlocked(), Agents: cfg.AgentNames(), Rules: cfg.Auto, TwoFA: cfg.TwoFA.Items,
		AgentListen: cfg.Agent.Listen, VaultServer: cfg.Vault.Server,
		Notice: notice, NoticeKind: kind, Query: r.URL.Query().Get("q"), Version: s.Version,
	}
	if cfg.Approver.BindIP != "" {
		v.Host = cfg.Approver.BindIP
	}
	if s.Linker != nil {
		base, _ := s.linkBase.Load().(string)
		for _, pr := range s.Store.Open() {
			v.Pending = append(v.Pending, adminPending{
				Agent: pr.Agent, Item: pr.Item.Name, Field: pr.Field.String(), Reason: pr.Reason,
				Link: base + "/a/" + s.Linker.Sign(pr.ID, pr.Expires), Expires: pr.Expires,
			})
		}
	}
	v.Health = s.Health(r.Context())
	if v.Query != "" && s.Vault.Unlocked() {
		items, err := s.Vault.Search(r.Context(), v.Query)
		if err == nil {
			for _, it := range items {
				v.Items = append(v.Items, adminItem{ID: it.ID, Name: it.Name, Folder: it.Folder, Fields: strings.Join(it.Fields, ", ")})
			}
		}
	}
	s.adminRender(w, r, v)
}

func (s *Server) adminRender(w http.ResponseWriter, _ *http.Request, v adminView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = adminPage.Execute(w, v)
}

// adminTest runs one dependency check and shows the result.
func (s *Server) adminTest(w http.ResponseWriter, r *http.Request, what string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	kind, msg := s.Test(ctx, what)
	s.adminHome(w, r, msg, kind)
}

// adminUnlock unlocks the vault with the master password of the agents account.
func (s *Server) adminUnlock(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pw := r.PostForm.Get("password")
	if strings.TrimSpace(pw) == "" {
		s.adminHome(w, r, "Type the master password of the agents account.", "bad")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.UnlockVault(ctx, pw); err != nil {
		s.adminHome(w, r, "The vault did not unlock: "+err.Error(), "bad")
		return
	}
	s.adminHome(w, r, "The vault is unlocked.", "ok")
}

func (s *Server) adminMutate(w http.ResponseWriter, r *http.Request, notice string, fn func(*config.Config) error) {
	if s.UpdateConfig == nil {
		http.Error(w, "config updates are not available", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if err := s.UpdateConfig(fn); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	s.audit("admin_config", "admin")
	s.adminHome(w, r, notice, "ok")
}

func (s *Server) adminBind(w http.ResponseWriter, r *http.Request) {
	s.adminMutate(w, r, "Saved. The approval address updates within 30 seconds. The agent address needs a restart.", func(c *config.Config) error {
		host := strings.TrimSpace(r.PostForm.Get("host"))
		if ip, err := netip.ParseAddr(host); err == nil {
			c.Approver.BindIP = ip.String()
			c.Approver.BindHost = ""
		} else if host != "" {
			c.Approver.BindHost = host
			c.Approver.BindIP = ""
		}
		if p := strings.TrimSpace(r.PostForm.Get("port")); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return err
			}
			c.Approver.Port = n
		}
		if h := strings.TrimSpace(r.PostForm.Get("public_host")); h != "" {
			c.Approver.PublicHost = h
		}
		if listen := strings.TrimSpace(r.PostForm.Get("agent_listen")); listen != "" {
			c.Agent.Listen = listen
		}
		return c.Validate()
	})
}

func (s *Server) adminNtfy(w http.ResponseWriter, r *http.Request) {
	s.adminMutate(w, r, "Notification settings saved.", func(c *config.Config) error {
		url := strings.TrimSpace(r.PostForm.Get("url"))
		domain := strings.TrimSpace(r.PostForm.Get("domain"))
		topic := strings.TrimSpace(r.PostForm.Get("topic"))
		if url == "" && domain == "" && topic == "" {
			c.Ntfy = config.Ntfy{}
			return c.Validate()
		}
		c.Ntfy.URL = url
		c.Ntfy.OwnDomain = domain
		c.Ntfy.Topic = topic
		if tok := strings.TrimSpace(r.PostForm.Get("token")); tok != "" {
			c.Ntfy.Token = tok
		}
		if _, err := notify.FromConfig(c.Ntfy.URL, c.Ntfy.OwnDomain, c.Ntfy.Topic, c.Ntfy.Token); err != nil {
			return err
		}
		return c.Validate()
	})
}

// adminNtfyTest runs the same probes as startup and then sends one real push, so the operator
// sees both the access check and the delivery in one place.
func (s *Server) adminNtfyTest(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	n, err := notify.FromConfig(cfg.Ntfy.URL, cfg.Ntfy.OwnDomain, cfg.Ntfy.Topic, cfg.Ntfy.Token)
	if err != nil {
		s.adminHome(w, r, "Notification check failed: "+err.Error(), "bad")
		return
	}
	if n == nil {
		s.adminHome(w, r, "No ntfy is configured, so there is nothing to test.", "warn")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := n.RequireAuth(ctx); err != nil {
		s.adminHome(w, r, "Notification check failed: "+err.Error(), "bad")
		return
	}
	if err := n.Send(ctx, notify.Message{Title: "bw2fabroker test", Body: "The broker reached this topic with its bearer token. No action needed.", Priority: 3, Tags: []string{"bell"}}); err != nil {
		s.adminHome(w, r, "Test push failed: "+err.Error(), "bad")
		return
	}
	s.audit("ntfy_test", "admin")
	s.adminHome(w, r, "Test notification sent: anonymous publish and read are refused, the bearer token was accepted, and one push was delivered.", "ok")
}

func (s *Server) adminAgentAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	var token, hash string
	var err error
	for range 3 {
		token, hash, err = auth.NewAgentToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if hash != s.Config().Admin.TokenSHA256 || s.Config().Admin.TokenSHA256 == "" {
			break
		}
		token = ""
	}
	if token == "" {
		http.Error(w, "new agent token matched the admin token", http.StatusInternalServerError)
		return
	}
	if err := s.UpdateConfig(func(c *config.Config) error {
		if c.Agents == nil {
			c.Agents = map[string]config.Agent{}
		}
		if _, ok := c.Agents[name]; ok {
			return errString("an agent with that name already exists")
		}
		c.Agents[name] = config.Agent{TokenSHA256: hash, Created: time.Now().UTC()}
		return c.Validate()
	}); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	s.audit("admin_agent_add", "admin")
	v := adminView{Notice: "Agent added. Copy its token now.", NoticeKind: "ok", Secret: token, Version: s.Version}
	s.fill(r, &v)
	s.adminRender(w, r, v)
}

func (s *Server) adminAgentRemove(w http.ResponseWriter, r *http.Request) {
	s.adminMutate(w, r, "Agent removed.", func(c *config.Config) error {
		name := strings.TrimSpace(r.PostForm.Get("name"))
		delete(c.Agents, name)
		return c.Validate()
	})
}

func (s *Server) adminAuto(w http.ResponseWriter, r *http.Request, add bool) {
	s.adminMutate(w, r, "Auto rules saved.", func(c *config.Config) error {
		item := strings.TrimSpace(r.PostForm.Get("item"))
		field := strings.TrimSpace(r.PostForm.Get("field"))
		if add {
			c.Auto = append(c.Auto, config.AutoRule{ItemID: item, Field: field})
		} else {
			var next []config.AutoRule
			for _, rule := range c.Auto {
				if rule.ItemID == item && rule.Field == field {
					continue
				}
				next = append(next, rule)
			}
			c.Auto = next
		}
		return c.Validate()
	})
}

func (s *Server) admin2FA(w http.ResponseWriter, r *http.Request, add bool) {
	s.adminMutate(w, r, "Authenticator tags saved.", func(c *config.Config) error {
		item := strings.TrimSpace(r.PostForm.Get("item"))
		var next []string
		for _, id := range c.TwoFA.Items {
			if id != item {
				next = append(next, id)
			}
		}
		if add {
			next = append(next, item)
		}
		c.TwoFA.Items = next
		return c.Validate()
	})
}

func (s *Server) admin2FAEnroll(w http.ResponseWriter, r *http.Request) {
	secret, url, err := auth.NewTOTPSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.UpdateConfig(func(c *config.Config) error {
		c.TwoFA.Secret = secret
		return c.Validate()
	}); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	s.audit("admin_2fa_enroll", "admin")
	v := adminView{Notice: "Authenticator secret replaced. Add the address below before leaving this page.", NoticeKind: "ok", Secret: url, Version: s.Version}
	s.fill(r, &v)
	s.adminRender(w, r, v)
}

func (s *Server) adminPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pw := r.PostForm.Get("password")
	if pw != r.PostForm.Get("again") {
		s.adminHome(w, r, "The two passwords do not match.", "bad")
		return
	}
	if len([]rune(pw)) < auth.MinPasswordLen {
		s.adminHome(w, r, "The approval password is too short.", "bad")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.UpdateConfig(func(c *config.Config) error {
		c.ApprovalPassword = hash
		return nil
	}); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	s.audit("admin_password", "admin")
	s.adminHome(w, r, "Approval password changed.", "ok")
}

func (s *Server) adminRotateToken(w http.ResponseWriter, r *http.Request) {
	var token string
	if err := s.UpdateConfig(func(c *config.Config) error {
		var hash string
		var err error
		for range 3 {
			token, hash, err = auth.NewAgentToken()
			if err != nil {
				return err
			}
			if !c.AgentHasHash(hash) {
				break
			}
			token = ""
		}
		if token == "" {
			return errString("new admin token matched an agent token")
		}
		c.Admin.TokenSHA256 = hash
		return c.Validate()
	}); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "broker_admin", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit("admin_token_rotated", "admin")
	v := adminView{Notice: "Admin token replaced. The old token no longer works.", NoticeKind: "ok", Secret: token, Version: s.Version}
	s.fill(r, &v)
	s.adminRender(w, r, v)
}

func (s *Server) adminResume(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if _, ok := s.Config().Agents[name]; !ok {
		s.adminHome(w, r, "There is no agent with that name.", "bad")
		return
	}
	s.Resume(name)
	s.adminHome(w, r, "Agent resumed.", "ok")
}

func (s *Server) adminVault(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.PostForm.Get("server"))
	if err := config.ValidVaultServer(raw); err != nil {
		s.adminHome(w, r, err.Error(), "bad")
		return
	}
	if raw != "" {
		if v, ok := s.Vault.(interface {
			SetServer(ctx context.Context, rawURL string) error
		}); ok {
			if err := v.SetServer(r.Context(), raw); err != nil {
				s.adminHome(w, r, err.Error(), "bad")
				return
			}
		}
	}
	s.adminMutate(w, r, "Bitwarden server saved.", func(c *config.Config) error {
		c.Vault.Server = raw
		return c.Validate()
	})
}

func (s *Server) fill(r *http.Request, v *adminView) {
	cfg := s.Config()
	v.Mode = s.BindMode()
	v.Host = cfg.Approver.BindHost
	if cfg.Approver.BindIP != "" {
		v.Host = cfg.Approver.BindIP
	}
	v.Port = cfg.Approver.Port
	v.Public = cfg.Approver.PublicHost
	v.NtfyURL = cfg.Ntfy.URL
	v.Domain = cfg.Ntfy.OwnDomain
	v.Topic = cfg.Ntfy.Topic
	v.LAN = s.allowLAN.Load()
	v.Unlocked = s.Vault.Unlocked()
	v.Agents = cfg.AgentNames()
	v.Rules = cfg.Auto
	v.TwoFA = cfg.TwoFA.Items
	v.AgentListen = cfg.Agent.Listen
	v.VaultServer = cfg.Vault.Server
	if s.Linker != nil {
		base, _ := s.linkBase.Load().(string)
		for _, pr := range s.Store.Open() {
			v.Pending = append(v.Pending, adminPending{
				Agent: pr.Agent, Item: pr.Item.Name, Field: pr.Field.String(), Reason: pr.Reason,
				Link: base + "/a/" + s.Linker.Sign(pr.ID, pr.Expires), Expires: pr.Expires,
			})
		}
	}
	v.Health = s.Health(r.Context())
	_ = r
}

type errString string

func (e errString) Error() string { return string(e) }
