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
<style>
:root {
  color-scheme: light;
  --bg: #f5f5f7;
  --card: #fff;
  --fg: #1d1d1f;
  --muted: #6e6e73;
  --line: rgba(0,0,0,.08);
  --blue: #0071e3;
  --red: #d70015;
  --shadow: 0 1px 2px rgba(0,0,0,.04), 0 12px 32px rgba(0,0,0,.06);
  font: 17px/1.47 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
}
@media (prefers-reduced-transparency: reduce) { :root { --card: #fff; } }
body { margin: 0; background: var(--bg); color: var(--fg); }
main { max-width: 40rem; margin: 0 auto; padding: 2.75rem 1.25rem 4rem; }
h1 { font-size: 2rem; font-weight: 700; letter-spacing: -0.022em; line-height: 1.1; margin: 0 0 .35rem; }
h2 { font-size: .75rem; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); margin: 0 0 .7rem; }
p, li { margin: .4rem 0; }
.lead { color: var(--muted); font-size: .95rem; margin-bottom: 1.25rem; }
section { background: var(--card); border-radius: 18px; box-shadow: var(--shadow); padding: 1.05rem 1.15rem 1.15rem; margin: 0 0 1.15rem; }
label { display: block; font-size: .82rem; font-weight: 600; margin: .85rem 0 .3rem; }
input, button { font: inherit; }
input { width: 100%; box-sizing: border-box; padding: .7rem .8rem; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--fg); }
input:focus { outline: 2px solid #b3d7ff; border-color: var(--blue); }
button { border: 0; border-radius: 980px; padding: .55rem 1.05rem; background: var(--blue); color: #fff; font-weight: 600; }
button:active { transform: scale(.97); }
button.quiet { background: #e8e8ed; color: var(--fg); }
button.danger { background: transparent; color: var(--red); }
.warn { color: var(--red); font-weight: 600; }
.ok { color: #1d7a3a; font-weight: 600; }
code { font-size: .92em; overflow-wrap: anywhere; }
form.row { display: inline; }
form.row button { padding: .3rem .7rem; margin-left: .3rem; }
@media (prefers-reduced-motion: reduce) { button:active { transform: none; } }
</style></head><body><main>
{{if .Login}}
<h1>bw2fabroker admin</h1>
<p>This page is only on this machine. Agents do not use it.</p>
<form method="post" action="/admin/login">
<label for="token">Admin token</label>
<input id="token" name="token" type="password" autocomplete="current-password" required>
<p><button type="submit">Enter</button></p>
</form>
{{if .Notice}}<p class="warn">{{.Notice}}</p>{{end}}
{{else}}
<h1>bw2fabroker</h1>
<p>Loopback admin only. An agent calls the HTTP API with its own bearer token. It cannot open this page, and this token is not an agent token.</p>
<p>Phone page: <strong>{{.Mode}}</strong> {{.Host}}:{{.Port}}{{if .Public}} (links use {{.Public}}){{end}}</p>
{{if .LAN}}<p class="warn">LAN mode. A device on this network can open the approval page. The page still asks for the approval password.</p>{{end}}
<p>Vault: {{if .Unlocked}}<span class="ok">unlocked</span>{{else}}<span class="warn">locked</span>{{end}}</p>
<section><h2>Bitwarden server</h2>
<p>Bitwarden cloud, Vaultwarden, or Bitwarden's own self-hosted server. HTTPS, or HTTP only on localhost, a private address, or a tailnet address. Saving this runs <code>bw config server</code>. Startup does it again.</p>
<form method="post" action="/admin/vault">
<label for="vault_server">Server URL</label>
<input id="vault_server" name="server" value="{{.VaultServer}}" placeholder="https://vault.example.com" autocomplete="off">
<p><button type="submit">Save server</button></p>
</form></section>
{{if .Notice}}<p>{{.Notice}}</p>{{end}}
{{if .Secret}}<p>Shown once. It is not stored in the page after you leave. <code>{{.Secret}}</code></p>{{end}}
<section><h2>Approval password</h2>
<p>The password typed on the phone. Not the Bitwarden master password.</p>
<form method="post" action="/admin/password">
<label for="password">New password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<label for="again">Repeat</label>
<input id="again" name="again" type="password" autocomplete="new-password" required>
<p><button type="submit">Change approval password</button></p>
</form></section>
<section><h2>Where the phone connects</h2>
<p>A tailnet address or one private LAN address. The approval port updates within 30 seconds. The agent address needs a restart of the broker.</p>
<form method="post" action="/admin/bind">
<label for="host">Approval host</label>
<input id="host" name="host" value="{{.Host}}" placeholder="100.x.y.z or a LAN address">
<label for="port">Approval port</label>
<input id="port" name="port" value="{{.Port}}" inputmode="numeric">
<label for="public_host">Name used in links</label>
<input id="public_host" name="public_host" value="{{.Public}}" placeholder="optional">
<label for="agent_listen">Agent HTTP listen</label>
<input id="agent_listen" name="agent_listen" value="{{.AgentListen}}" placeholder="100.x.y.z:8786">
<p><button type="submit">Save addresses</button></p>
</form></section>
<section><h2>Notifications</h2>
<p>The topic must reject requests that have no bearer token. Leave every field empty to run without notifications; approval links then appear in the log and under "Waiting for approval".</p>
<form method="post" action="/admin/ntfy">
<label for="url">URL</label>
<input id="url" name="url" value="{{.NtfyURL}}" autocomplete="off">
<label for="domain">Own domain</label>
<input id="domain" name="domain" value="{{.Domain}}" autocomplete="off">
<label for="topic">Topic</label>
<input id="topic" name="topic" value="{{.Topic}}" autocomplete="off">
<label for="ntfy_token">Bearer token</label>
<input id="ntfy_token" name="token" type="password" placeholder="leave blank to keep the current token" autocomplete="off">
<p><button type="submit">Save notifications</button></p>
</form></section>
<section><h2>Waiting for approval</h2>
{{if .Pending}}<ul>{{range .Pending}}<li><a href="{{.Link}}">{{.Item}} / {{.Field}}</a> for {{.Agent}} — {{.Reason}} (expires {{.Expires.Format "15:04:05"}})</li>{{end}}</ul>
{{else}}<p>No request is waiting.</p>{{end}}</section>
<section><h2>Agents</h2>
<p>Adding an agent shows its bearer token once. Resume clears a suspension after three denials. Remove deletes the token.</p>
<ul>{{range .Agents}}<li>{{.}}
<form class="row" method="post" action="/admin/agent/resume"><input type="hidden" name="name" value="{{.}}"><button class="quiet" type="submit">Resume</button></form>
<form class="row" method="post" action="/admin/agent/remove"><input type="hidden" name="name" value="{{.}}"><button class="danger" type="submit">Remove</button></form>
</li>{{end}}</ul>
<form method="post" action="/admin/agent/add">
<label for="agent_name">Name</label>
<input id="agent_name" name="name" placeholder="letters, digits, _ or -" required>
<p><button type="submit">Add agent</button></p>
</form></section>
<section><h2>Auto rules</h2>
<p>These items are returned without asking. A TOTP field is never automatic.</p>
<ul>{{range .Rules}}<li><code>{{.ItemID}}</code> {{if .Field}}{{.Field}}{{else}}any field except totp{{end}}
<form class="row" method="post" action="/admin/auto/remove"><input type="hidden" name="item" value="{{.ItemID}}"><input type="hidden" name="field" value="{{.Field}}"><button class="quiet" type="submit">Remove</button></form>
</li>{{end}}</ul>
<form method="post" action="/admin/auto/add">
<label for="auto_item">Item id</label>
<input id="auto_item" name="item" required>
<label for="auto_field">Field</label>
<input id="auto_field" name="field" placeholder="blank means any field except totp">
<p><button type="submit">Allow without asking</button></p>
</form></section>
<section><h2>Authenticator</h2>
<p>Enroll replaces the secret. The old authenticator app stops working. The new address is shown once; add it before you leave this page.</p>
<form method="post" action="/admin/2fa/enroll"><button type="submit">Create authenticator secret</button></form>
<ul>{{range .TwoFA}}<li><code>{{.}}</code>
<form class="row" method="post" action="/admin/2fa/remove"><input type="hidden" name="item" value="{{.}}"><button type="submit">Stop asking</button></form>
</li>{{end}}</ul>
<form method="post" action="/admin/2fa/add">
<label for="twofa_item">Item id that asks for a code</label>
<input id="twofa_item" name="item" required>
<p><button type="submit">Require a code</button></p>
</form></section>
<section><h2>Vault names</h2>
<p>Names and field names only. This page cannot run arbitrary Bitwarden commands.</p>
<form method="get" action="/admin/search">
<label for="q">Search</label>
<input id="q" name="q" value="{{.Query}}">
<p><button type="submit">Search</button></p>
</form>
<ul>{{range .Items}}<li>{{.Name}}{{if .Folder}} ({{.Folder}}){{end}} <code>{{.ID}}</code> {{.Fields}}</li>{{end}}</ul>
</section>
<section><h2>Admin token</h2>
<p>Replacing the token signs this browser in with the new one. The old token stops working.</p>
<form method="post" action="/admin/token"><button type="submit">Replace admin token</button></form>
</section>
{{end}}
</main>
</body></html>`))

type adminPending struct {
	Agent, Item, Field, Reason, Link string
	Expires                          time.Time
}

type adminView struct {
	Login                                                                                             bool
	Mode, Host, Public, NtfyURL, Domain, Topic, Notice, Secret, Query, AgentListen, Bind, VaultServer string
	Port                                                                                              int
	LAN, Unlocked                                                                                     bool
	Agents                                                                                            []string
	Pending                                                                                           []adminPending
	Rules                                                                                             []config.AutoRule
	TwoFA                                                                                             []string
	Items                                                                                             []adminItem
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
			s.adminRender(w, r, adminView{Login: true})
			return
		}
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/admin" || r.URL.Path == "/admin/search"):
			s.adminHome(w, r, "")
		case r.Method == http.MethodPost && r.URL.Path == "/admin/bind":
			s.adminBind(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/ntfy":
			s.adminNtfy(w, r)
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
		s.adminRender(w, r, adminView{Login: true, Notice: "Wrong token."})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "broker_admin", Value: strings.TrimSpace(r.PostForm.Get("token")), Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode})
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

func (s *Server) adminHome(w http.ResponseWriter, r *http.Request, notice string) {
	var v adminView
	s.fill(r, &v)
	v.Notice = notice
	v.Query = r.URL.Query().Get("q")
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = adminPage.Execute(w, v)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit("admin_config", "admin")
	s.adminHome(w, r, notice)
}

func (s *Server) adminBind(w http.ResponseWriter, r *http.Request) {
	s.adminMutate(w, r, "Saved. The approval address updates within 30 seconds. The agent address needs a restart.", func(c *config.Config) error {
		host := strings.TrimSpace(r.PostForm.Get("host"))
		if ip, err := netip.ParseAddr(host); err == nil {
			c.Approver.BindIP = ip.String()
			c.Approver.BindHost = ""
		} else {
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
		c.Approver.PublicHost = strings.TrimSpace(r.PostForm.Get("public_host"))
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit("admin_agent_add", "admin")
	cfg := s.Config()
	v := adminView{Notice: "Agent added.", Secret: token, Agents: cfg.AgentNames()}
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit("admin_2fa_enroll", "admin")
	v := adminView{Notice: "Authenticator secret replaced. Add the address below before leaving this page.", Secret: url}
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
		s.adminHome(w, r, "The two passwords do not match.")
		return
	}
	if len([]rune(pw)) < auth.MinPasswordLen {
		s.adminHome(w, r, "The approval password is too short.")
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit("admin_password", "admin")
	s.adminHome(w, r, "Approval password changed.")
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "broker_admin", Value: token, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit("admin_token_rotated", "admin")
	v := adminView{Notice: "Admin token replaced. The old token no longer works.", Secret: token}
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
		http.Error(w, "no such agent", http.StatusBadRequest)
		return
	}
	s.Resume(name)
	s.adminHome(w, r, "Agent resumed.")
}
func (s *Server) adminVault(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.PostForm.Get("server"))
	if err := config.ValidVaultServer(raw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if raw != "" {
		if v, ok := s.Vault.(interface {
			SetServer(ctx context.Context, rawURL string) error
		}); ok {
			if err := v.SetServer(r.Context(), raw); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
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
	_ = r
}

type errString string

func (e errString) Error() string { return string(e) }
