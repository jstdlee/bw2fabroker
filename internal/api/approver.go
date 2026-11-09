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

// pageCSS is the phone look of the approval page: the same tokens as the panel, with
// larger type and 48 px buttons.
const pageCSS = `
:root {
  color-scheme: light dark;
  --bg: #f4f4f6; --card: #ffffff; --line: #e3e3e8; --divider: #ececf0;
  --fg: #212126; --dim: #737379; --track: #f1f1f4; --accent: #007aff; --bad: #d70015;
  font: 16px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  -webkit-text-size-adjust: 100%;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1c1c1f; --card: #252528; --line: #303034; --divider: #2c2c30;
    --fg: #e8e8ec; --dim: #8e8e96; --track: #2e2e33; --accent: #0a84ff; --bad: #ff453a;
  }
}
@media (prefers-contrast: more) { :root { --dim: #5c5c63; --line: #b9b9c0; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); }
main { max-width: 26rem; margin: 0 auto; padding: 18px 16px 40px; }
.wordmark { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--dim); }
h1 { font-size: 22px; font-weight: 600; letter-spacing: -.015em; margin: 5px 0 14px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 2px 14px; margin: 0 0 12px; }
.row { display: flex; gap: 12px; padding: 10px 0; border-top: 1px solid var(--divider); }
.row:first-child { border-top: 0; }
.k { flex: 0 0 5.6rem; color: var(--dim); font-size: 13px; padding-top: 1px; }
.v { margin: 0; font-size: 14.5px; overflow-wrap: anywhere; }
.v .id { display: block; color: var(--dim); font-size: 11.5px; margin-top: 2px; }
.reason { display: block; background: var(--track); border-radius: 8px; padding: 8px 10px; }
.demo { background: #fff6e0; color: #6b4b00; border-radius: 10px; padding: 10px 12px; font-size: 13px; margin: 0 0 12px; }
.status { font-size: 15px; margin: 0 0 12px; }
label { display: block; font-size: 12.5px; color: var(--dim); margin: 0 0 5px; }
input { width: 100%; font: inherit; font-size: 17px; padding: 11px 12px; border-radius: 10px; border: 1px solid var(--line); background: var(--track); color: var(--fg); min-height: 46px; }
input:focus { outline: 3px solid color-mix(in srgb, var(--accent) 45%, transparent); outline-offset: 1px; border-color: var(--accent); }
button { font: inherit; font-weight: 600; font-size: 16px; width: 100%; min-height: 48px; border-radius: 10px; border: 0; margin-top: 8px; cursor: default; user-select: none; }
.approve { background: var(--accent); color: #fff; }
.approve:active { background: color-mix(in srgb, var(--accent) 88%, #000); }
.deny { background: transparent; color: var(--bad); }
.small { color: var(--dim); font-size: 12.5px; margin: 12px 0 0; }
@media (prefers-color-scheme: dark) { .demo { background: #33290f; color: #f0d493; } }
@media (prefers-reduced-motion: reduce) { button:active { background: none; } }
`

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>bw2fabroker</title>
<style>` + pageCSS + `</style></head><body><main>
{{if .Pending}}
<div class="wordmark">bw2fabroker</div>
<h1>Approve one secret?</h1>
{{if .Demo}}<p class="demo">Demo on this machine. Not your Bitwarden vault. Use the approval password printed when <code>broker demo</code> started.</p>{{end}}
<div class="card">
<div class="row"><span class="k">Agent</span><p class="v">{{.Agent}}</p></div>
<div class="row"><span class="k">Item</span><p class="v">{{.ItemName}}<span class="id">{{.ItemID}}</span></p></div>
<div class="row"><span class="k">Field</span><p class="v"><strong>{{.Field}}</strong>{{if .IsTOTP}} · a second factor{{end}}</p></div>
<div class="row"><span class="k">Folder</span><p class="v">{{if .Folder}}{{.Folder}}{{else}}none{{end}}</p></div>
<div class="row"><span class="k">Reason</span><p class="v"><span class="reason">{{.Reason}}</span></p></div>
<div class="row"><span class="k">Expires</span><p class="v">in {{.SecondsLeft}} seconds</p></div>
</div>
{{if .Message}}<p class="status">{{.Message}}</p>{{end}}
<form method="post" action="{{.Base}}/approve" autocomplete="off">
<label for="pw">Approval password</label>
<input id="pw" name="password" type="password" autocomplete="off" required autofocus>
{{if .Need2FA}}<label for="code">Authenticator code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>{{end}}
<button class="approve" type="submit">Approve</button>
</form>
<form method="post" action="{{.Base}}/deny"><button class="deny" type="submit">Deny</button></form>
<p class="small">This password releases this one field only. It is not your Bitwarden master password.</p>
{{else}}
<div class="wordmark">bw2fabroker</div>
<h1>{{.Title}}</h1>
<p class="status">{{.Message}}</p>
{{end}}
</main></body></html>`))

type pageData struct {
	Pending                                bool
	Agent, ItemName, ItemID, Folder, Field string
	Reason, Base, Message, Title           string
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
	s.render(w, status, pageData{Title: "bw2fabroker", Message: msg})
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
