package api

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/pending"
)

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>bw2fabroker</title>
<style>
:root{color-scheme:light;--bg:#f5f5f7;--card:#fff;--fg:#1d1d1f;--muted:#6e6e73;--line:rgba(0,0,0,.08);--blue:#0071e3;--red:#d70015}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.47 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:28rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.7rem;font-weight:700;letter-spacing:-.022em;line-height:1.15;margin:0 0 1rem}
.card{background:var(--card);border-radius:18px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 12px 32px rgba(0,0,0,.06);padding:1rem 1rem .4rem;margin:0 0 1rem}
dl{display:grid;grid-template-columns:5.5rem 1fr;gap:.55rem .75rem;margin:0}
dt{color:var(--muted);font-size:.82rem;padding-top:.15rem}dd{margin:0;overflow-wrap:anywhere}
.reason{background:#f5f5f7;border-radius:12px;padding:.55rem .7rem}
.small{color:var(--muted);font-size:.82rem}
label{display:block;font-size:.82rem;font-weight:600;margin:.2rem 0 .3rem}
input{width:100%;box-sizing:border-box;font:inherit;font-size:1.05rem;padding:.75rem .8rem;margin:0 0 .8rem;border:1px solid var(--line);border-radius:12px;background:#fff;color:var(--fg)}
input:focus{outline:2px solid #b3d7ff;border-color:var(--blue)}
button{font:inherit;font-weight:600;font-size:1.05rem;padding:.85rem;border-radius:980px;border:0;width:100%;margin-bottom:.6rem}
button:active{transform:scale(.97)}
.approve{background:var(--blue);color:#fff}.deny{background:#e8e8ed;color:var(--red)}
.status{font-size:1.15rem;font-weight:650;letter-spacing:-.01em}
.demo{background:#fff8e8;border-radius:12px;padding:.7rem .8rem;margin:0 0 .9rem}
@media (prefers-reduced-motion:reduce){button:active{transform:none}}
</style></head><body><main>
{{if .Pending}}
<h1>Approve one secret?</h1>
{{if .Demo}}<p class="demo">Demo on this machine. Not your Bitwarden vault. Use the approval password printed when <code>broker demo</code> started.</p>{{end}}
<div class="card"><dl>
<dt>Agent</dt><dd>{{.Agent}}</dd>
<dt>Item</dt><dd>{{.ItemName}}</dd>
<dt>Item id</dt><dd><code>{{.ItemID}}</code></dd>
<dt>Folder</dt><dd>{{if .Folder}}{{.Folder}}{{else}}(none){{end}}</dd>
<dt>Field</dt><dd><strong>{{.Field}}</strong>{{if .IsTOTP}} — a second factor{{end}}</dd>
<dt>Reason</dt><dd class="reason">{{.Reason}}<br><span class="small">the agent's own words</span></dd>
<dt>Expires</dt><dd>in {{.SecondsLeft}} s</dd>
</dl></div>
{{if .Message}}<p class="status">{{.Message}}</p>{{end}}
<form method="post" action="{{.Base}}/approve" autocomplete="off">
<label for="pw">Approval password</label>
<input id="pw" name="password" type="password" autocomplete="off" required autofocus>
{{if .Need2FA}}<label for="code">Authenticator code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>{{end}}
<button class="approve" type="submit">Approve</button>
</form>
<form method="post" action="{{.Base}}/deny"><button class="deny" type="submit">Deny</button></form>
<p class="small">Never type your Bitwarden master password here.</p>
{{else}}
<h1>bw2fabroker</h1>
<p class="status">{{.Message}}</p>
{{end}}
</main></body></html>`))

type pageData struct {
	Pending                                bool
	Agent, ItemName, ItemID, Folder, Field string
	Reason, Base, Message                  string
	IsTOTP, Demo, Need2FA                  bool
	SecondsLeft                            int
}

func (s *Server) render(w http.ResponseWriter, status int, d pageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = page.Execute(w, d)
}

func (s *Server) message(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, pageData{Message: msg})
}

// ApproverHandler serves /a only. It answers only callers with a tailnet address.
func (s *Server) ApproverHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic in approver handler", slog.Any("panic", rec))
				s.message(w, http.StatusInternalServerError, "Internal error.")
			}
		}()
		if !s.callerMayApprove(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.serveApprover(w, r)
	})
}

func (s *Server) serveApprover(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/a/")
	if !ok || rest == "" {
		http.NotFound(w, r)
		return
	}
	token, action, _ := strings.Cut(rest, "/")
	id, err := s.Linker.Verify(token, s.Now())
	if errors.Is(err, auth.ErrBadLink) {
		s.message(w, http.StatusNotFound, "This link is not valid.")
		return
	}
	if errors.Is(err, auth.ErrExpiredLink) {
		s.message(w, http.StatusGone, "This request has expired.")
		return
	}
	base := "/a/" + token
	switch {
	case action == "" && r.Method == http.MethodGet:
		s.showRequest(w, id, base, "")
	case action == "approve" && r.Method == http.MethodPost:
		s.approve(w, r, id, base)
	case action == "callback" && r.Method == http.MethodPost:
		s.showRequest(w, id, base, "Open this page and type the approval password. A notification button cannot approve by itself.")
	case action == "deny" && r.Method == http.MethodPost:
		s.deny(w, id)
	default:
		http.NotFound(w, r)
	}
}

func finishedMessage(v pending.View) string {
	switch {
	case v.Status == contract.StatusApproved:
		return "Approved. The agent receives the secret once."
	case v.Code == contract.CodeExpired:
		return "This request has expired."
	case v.Code == contract.CodeDeniedByUser:
		return "Denied."
	case v.Code == contract.CodeTooManyPasswordErrors:
		return "Denied after too many wrong passwords."
	}
	return "This request is closed."
}

func (s *Server) showRequest(w http.ResponseWriter, id, base, msg string) {
	v, ok := s.Store.Get(id)
	if !ok {
		s.message(w, http.StatusNotFound, "This request is closed or unknown (the broker may have restarted).")
		return
	}
	if !v.Pending {
		s.message(w, http.StatusOK, finishedMessage(v))
		return
	}
	left := int(time.Until(v.Expires).Seconds())
	if n := int(v.Expires.Sub(s.Now()).Seconds()); n < left {
		left = n
	}
	s.render(w, http.StatusOK, pageData{
		Pending: true, Demo: s.AllowLoopback, Agent: v.Agent, ItemName: v.Item.Name, ItemID: v.Item.ID, Folder: v.Item.Folder,
		Field: v.Field.String(), IsTOTP: v.Field.Kind == "totp", Need2FA: s.Config().Requires2FA(v.Item.ID), Reason: v.Reason, Base: base,
		SecondsLeft: max(left, 0), Message: msg,
	})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, id, base string) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		s.message(w, http.StatusBadRequest, "Bad form.")
		return
	}
	v, ok := s.Store.Get(id)
	if !ok || !v.Pending {
		s.showRequest(w, id, base, "")
		return
	}
	if s.ApprovalsLocked() {
		s.message(w, http.StatusForbidden, "Approvals are locked after too many wrong passwords. Run `broker unlock-approvals`.")
		return
	}
	pw := r.PostForm.Get("password")
	if !auth.VerifyPassword(s.Config().ApprovalPassword, pw) {
		if s.wrongPassword(id, v.Agent) {
			s.showRequest(w, id, base, "")
			return
		}
		s.showRequest(w, id, base, "Wrong password.")
		return
	}
	if s.Config().Requires2FA(v.Item.ID) {
		secret := s.Config().TwoFA.Secret
		code := strings.TrimSpace(r.PostForm.Get("code"))
		if secret == "" || !auth.VerifyTOTP(secret, code, s.Now()) {
			s.showRequest(w, id, base, "Wrong authenticator code.")
			return
		}
	}
	req, err := s.Store.Claim(id)
	if err != nil {
		s.showRequest(w, id, base, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	value, err := s.Vault.Read(ctx, req.Item.ID, req.Field)
	attrs := []slog.Attr{slog.String("request_id", id), slog.String("item_id", req.Item.ID), slog.String("field", req.Field.String()), slog.String("remote", r.RemoteAddr)}
	if code := vaultCode(err); code != "" {
		s.logVaultErr(req.Agent, err, code)
		_, _ = s.Store.Finish(id, contract.Rejected(id, code))
		s.message(w, http.StatusOK, "Approved, but the vault read failed ("+string(code)+"). The agent was told.")
		return
	}
	if contract.ValidValue(value) != nil {
		_, _ = s.Store.Finish(id, contract.Rejected(id, contract.CodeValueTooLarge))
		s.audit("rejected", req.Agent, append(attrs, slog.String("code", "value_too_large"))...)
		s.message(w, http.StatusOK, "The value is too large or has control characters, so it was not sent.")
		return
	}
	if err := s.Store.Approve(id, value); err != nil {
		s.showRequest(w, id, base, "")
		return
	}
	s.audit("approved", req.Agent, attrs...)
	s.message(w, http.StatusOK, "Approved. The agent receives the secret once.")
}

func (s *Server) deny(w http.ResponseWriter, id string) {
	req, err := s.Store.Finish(id, contract.Denied(id, contract.CodeDeniedByUser))
	if err != nil {
		v, ok := s.Store.Get(id)
		if !ok {
			s.message(w, http.StatusNotFound, "This request is closed or unknown.")
			return
		}
		s.message(w, http.StatusOK, finishedMessage(v))
		return
	}
	s.audit("denied", req.Agent, slog.String("request_id", id), slog.String("code", "denied_by_user"))
	s.recordDenial(req.Agent)
	s.message(w, http.StatusOK, "Denied.")
}
