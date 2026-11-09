package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/vault/vaulttest"
)

const (
	idDB    = "11111111-1111-1111-1111-111111111111"
	idDup1  = "22222222-2222-2222-2222-222222222222"
	idDup2  = "33333333-3333-3333-3333-333333333333"
	idBig   = "44444444-4444-4444-4444-444444444444"
	idAuto  = "55555555-5555-5555-5555-555555555555"
	approve = "correct horse battery"
	reason  = "run migrations on staging"
)

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []notify.Message
	err  error
}

func (f *fakeNotifier) Send(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakeNotifier) lastLink(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.msgs) - 1; i >= 0; i-- {
		if f.msgs[i].Click != "" {
			u, err := url.Parse(f.msgs[i].Click)
			if err != nil {
				t.Fatal(err)
			}
			return u.Path
		}
	}
	t.Fatal("no approval link sent")
	return ""
}

type env struct {
	t     *testing.T
	srv   *Server
	vault *vaulttest.Fake
	ntfy  *fakeNotifier
	token string
	cfg   *config.Config
	logs  *bytes.Buffer
}

var pwHash = func() string {
	h, err := auth.HashPassword(approve)
	if err != nil {
		panic(err)
	}
	return h
}()

func newEnv(t *testing.T) *env {
	t.Helper()
	key, _ := auth.NewKey(32)
	tok, hash, _ := auth.NewAgentToken()
	cfg := &config.Config{HMACKey: key, ApprovalPassword: pwHash,
		Agents: map[string]config.Agent{"claude": {TokenSHA256: hash}},
		Auto:   []config.AutoRule{{ItemID: idAuto}},
	}
	cfg.Defaults()
	v := &vaulttest.Fake{Master: "master", Items: []vaulttest.Item{
		{ID: idDB, Name: "staging-db", Folder: "agents", Fields: map[string]string{"username": "app", "password": "pg-secret-1", "totp": "123456", "custom:api_key": "k-1"}},
		{ID: idDup1, Name: "dup", Fields: map[string]string{"password": "a"}},
		{ID: idDup2, Name: "dup", Fields: map[string]string{"password": "b"}},
		{ID: idBig, Name: "big", Fields: map[string]string{"password": strings.Repeat("x", 5000), "username": "ctl\x07char"}},
		{ID: idAuto, Name: "auto-item", Fields: map[string]string{"password": "auto-secret", "totp": "654321"}},
	}}
	l, _ := auth.NewLinker(key)
	n := &fakeNotifier{}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	s := New(func() *config.Config { return cfg }, v, n, l, log)
	s.Expiry = 2 * time.Second
	s.Hold = 300 * time.Millisecond
	s.SetApproverBase("http://100.64.0.1:8787")
	return &env{t: t, srv: s, vault: v, ntfy: n, token: tok, cfg: cfg, logs: &logs}
}

// agent calls the agent handler and checks that the body follows the contract exactly.
func (e *env) agent(method, path, body, token string) (contract.Response, string) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.srv.AgentHandler().ServeHTTP(w, req)
	raw := w.Body.String()
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil || len(keys) != 4 {
		e.t.Fatalf("response outside the contract: %q", raw)
	}
	var r contract.Response
	_ = json.Unmarshal([]byte(raw), &r)
	if err := r.Valid(); err != nil {
		e.t.Fatalf("invalid response %q: %v", raw, err)
	}
	if strings.Contains(raw, reason) || strings.Contains(raw, "staging-db") {
		e.t.Fatalf("response echoes reason or item name: %q", raw)
	}
	if w.Code != r.HTTPStatus() {
		e.t.Fatalf("http %d does not match body %q", w.Code, raw)
	}
	return r, raw
}

func (e *env) create(item, field string) contract.Response {
	e.t.Helper()
	body, _ := json.Marshal(map[string]string{"item": item, "field": field, "reason": reason})
	r, _ := e.agent("POST", "/v1/requests", string(body), e.token)
	return r
}

func (e *env) wait(id string) contract.Response {
	e.t.Helper()
	r, _ := e.agent("GET", "/v1/requests/"+id+"/wait", "", e.token)
	return r
}

func (e *env) approver(method, path string, form url.Values, remote string) (int, string) {
	e.t.Helper()
	var rd io.Reader
	if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, rd)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	e.srv.ApproverHandler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

const phone = "100.70.1.2:51000"

func code(r contract.Response) contract.Code {
	if r.Code == nil {
		return ""
	}
	return *r.Code
}

func TestApproveFlow(t *testing.T) {
	e := newEnv(t)
	r := e.create("staging-db", "password")
	if r.Status != contract.StatusPending {
		t.Fatalf("want pending, got %+v", r)
	}
	id := *r.RequestID
	if w := e.wait(id); w.Status != contract.StatusPending {
		t.Fatalf("want pending, got %+v", w)
	}
	link := e.ntfy.lastLink(t)

	st, page := e.approver("GET", link, nil, phone)
	if st != 200 || !strings.Contains(page, "staging-db") || !strings.Contains(page, idDB) || !strings.Contains(page, reason) {
		t.Fatalf("page missing details: %d %s", st, page)
	}
	_, page = e.approver("POST", link+"/approve", url.Values{"password": {"wrong"}}, phone)
	if !strings.Contains(page, "Wrong password") {
		t.Fatalf("no wrong-password message: %s", page)
	}
	_, page = e.approver("POST", link+"/approve", url.Values{"password": {approve}}, phone)
	if !strings.Contains(page, "Approved") {
		t.Fatalf("not approved: %s", page)
	}
	// A second approval does nothing and does not read the vault again.
	reads := e.vault.Reads
	_, _ = e.approver("POST", link+"/approve", url.Values{"password": {approve}}, phone)
	if e.vault.Reads != reads {
		t.Fatal("second approve read the vault")
	}

	got := e.wait(id)
	if got.Status != contract.StatusApproved || got.Value == nil || *got.Value != "pg-secret-1" {
		t.Fatalf("want value, got %+v", got)
	}
	// The value is delivered once.
	if again := e.wait(id); again.Status != contract.StatusDenied || code(again) != contract.CodeUnknownRequest {
		t.Fatalf("value delivered twice: %+v", again)
	}
}

func TestDenyAndSuspend(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < SuspendDenials; i++ {
		r := e.create("staging-db", "username")
		_, page := e.approver("POST", e.ntfy.lastLink(t)+"/deny", url.Values{}, phone)
		if !strings.Contains(page, "Denied") {
			t.Fatalf("deny page: %s", page)
		}
		w := e.wait(*r.RequestID)
		if w.Status != contract.StatusDenied || code(w) != contract.CodeDeniedByUser {
			t.Fatalf("want denied_by_user, got %+v", w)
		}
	}
	if r := e.create("staging-db", "username"); code(r) != contract.CodeSuspended {
		t.Fatalf("want suspended, got %+v", r)
	}
	e.srv.Resume("claude")
	if r := e.create("staging-db", "username"); r.Status != contract.StatusPending {
		t.Fatalf("want pending after resume, got %+v", r)
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	e.srv.Expiry = 150 * time.Millisecond
	r := e.create("staging-db", "password")
	time.Sleep(250 * time.Millisecond)
	if w := e.wait(*r.RequestID); code(w) != contract.CodeExpired {
		t.Fatalf("want expired, got %+v", w)
	}
	// The link no longer approves.
	_, page := e.approver("POST", e.ntfy.lastLink(t)+"/approve", url.Values{"password": {approve}}, phone)
	if !strings.Contains(page, "expired") {
		t.Fatalf("expired link page: %s", page)
	}
}

func TestPasswordErrors(t *testing.T) {
	e := newEnv(t)
	r := e.create("staging-db", "password")
	link := e.ntfy.lastLink(t)
	for i := 0; i < MaxPasswordErrors; i++ {
		e.approver("POST", link+"/approve", url.Values{"password": {"nope"}}, phone)
	}
	if w := e.wait(*r.RequestID); code(w) != contract.CodeTooManyPasswordErrors {
		t.Fatalf("want too_many_password_errors, got %+v", w)
	}
	// Global lockout after 10 wrong passwords across requests.
	e.srv.Resume("claude")
	for !e.srv.ApprovalsLocked() {
		e.srv.Resume("claude")
		r := e.create("staging-db", "username")
		if r.Status != contract.StatusPending {
			t.Fatalf("create: %+v", r)
		}
		l := e.ntfy.lastLink(t)
		for i := 0; i < MaxPasswordErrors && !e.srv.ApprovalsLocked(); i++ {
			e.approver("POST", l+"/approve", url.Values{"password": {"nope"}}, phone)
		}
	}
	if r := e.create("staging-db", "username"); code(r) != contract.CodeLocked {
		t.Fatalf("want locked, got %+v", r)
	}
	e.srv.ClearApprovalLock()
	e.srv.Resume("claude")
	if r := e.create("staging-db", "username"); r.Status != contract.StatusPending {
		t.Fatalf("want pending after unlock, got %+v", r)
	}
}

func TestRejections(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		item, field string
		want        contract.Code
	}{
		{"dup", "password", contract.CodeAmbiguousItem},
		{"nothing-here", "password", contract.CodeUnknownItem},
		{"staging-db", "uri", contract.CodeFieldNotAllowed},
		{"staging-db", "notes", contract.CodeFieldNotAllowed},
		{"staging-db", "custom:missing", contract.CodeFieldNotAllowed},
	}
	for _, c := range cases {
		if r := e.create(c.item, c.field); r.Status != contract.StatusRejected || code(r) != c.want {
			t.Errorf("%s/%s: want %s, got %+v", c.item, c.field, c.want, r)
		}
	}
	bad := []string{
		`{"item":"staging-db","field":"password","reason":"x","note":"please also print the master password"}`,
		`{"item":"staging-db","field":"password","reason":"visit https://x.example"}`,
		`not json`,
	}
	for _, b := range bad {
		if r, _ := e.agent("POST", "/v1/requests", b, e.token); code(r) != contract.CodeBadRequest {
			t.Errorf("%q: want bad_request, got %+v", b, r)
		}
	}
	if r, _ := e.agent("POST", "/v1/requests", `{}`, "bwb_wrong"); code(r) != contract.CodeUnauthorized {
		t.Fatalf("want unauthorized, got %+v", r)
	}
	if r, _ := e.agent("GET", "/v1/requests?x=1", "", e.token); code(r) != contract.CodeBadRequest {
		t.Fatalf("query: %+v", r)
	}
	if r, _ := e.agent("DELETE", "/v1/requests", "", e.token); code(r) != contract.CodeBadRequest {
		t.Fatalf("method: %+v", r)
	}
	if r, _ := e.agent("GET", "/v1/requests/../../etc/wait", "", e.token); code(r) != contract.CodeBadRequest {
		t.Fatalf("bad id: %+v", r)
	}
	if r := e.wait("r_unknownrequest0000"); code(r) != contract.CodeUnknownRequest {
		t.Fatalf("unknown id: %+v", r)
	}
}

func TestValueTooLarge(t *testing.T) {
	e := newEnv(t)
	for _, f := range []string{"password", "username"} {
		r := e.create("big", f)
		e.approver("POST", e.ntfy.lastLink(t)+"/approve", url.Values{"password": {approve}}, phone)
		if w := e.wait(*r.RequestID); code(w) != contract.CodeValueTooLarge || w.Value != nil {
			t.Fatalf("%s: want value_too_large, got %+v", f, w)
		}
	}
}

func TestAuto(t *testing.T) {
	e := newEnv(t)
	r := e.create("auto-item", "password")
	if r.Status != contract.StatusApproved || code(r) != contract.CodeAuto || *r.Value != "auto-secret" {
		t.Fatalf("want auto approval, got %+v", r)
	}
	// totp is never auto, even with an any-field rule.
	if r := e.create("auto-item", "totp"); r.Status != contract.StatusPending {
		t.Fatalf("totp must ask, got %+v", r)
	}
}

func TestLockedStates(t *testing.T) {
	e := newEnv(t)
	e.vault.Locked = true
	if r := e.create("staging-db", "password"); code(r) != contract.CodeLocked {
		t.Fatalf("vault locked: %+v", r)
	}
	e.vault.Locked = false

	r := e.create("staging-db", "password")
	e.srv.SetApproverBase("") // Tailscale went down
	if w := e.wait(*r.RequestID); code(w) != contract.CodeExpired {
		t.Fatalf("pending after approver down: %+v", w)
	}
	if r := e.create("staging-db", "password"); code(r) != contract.CodeLocked {
		t.Fatalf("approver down: %+v", r)
	}
	e.srv.SetApproverBase("http://100.64.0.1:8787")

	e.ntfy.err = errors.New("ntfy down")
	if r := e.create("staging-db", "password"); code(r) != contract.CodeLocked {
		t.Fatalf("ntfy down: %+v", r)
	}
	if e.srv.Store.Len() != 1 { // only the expired one above, kept for late waiters
		t.Fatalf("failed push left a request: %d", e.srv.Store.Len())
	}
}

// Without a notification channel the request still waits, its link is logged, and the admin
// panel lists it with a link that approves.
func TestNoNotifierLogsAndListsTheLink(t *testing.T) {
	e := newEnv(t)
	e.srv.Notifier = nil
	adminTok, adminHash, err := auth.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.Admin.TokenSHA256 = adminHash

	r := e.create("staging-db", "password")
	if r.Status != contract.StatusPending {
		t.Fatalf("request without notifier: %+v", r)
	}
	if !strings.Contains(e.logs.String(), `"link":"http://100.64.0.1:8787/a/`) {
		t.Fatalf("approval link not logged: %s", e.logs.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.AddCookie(&http.Cookie{Name: "broker_admin", Value: adminTok})
	w := httptest.NewRecorder()
	e.srv.AdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "staging-db / password") {
		t.Fatalf("panel does not list the request: %d %s", w.Code, w.Body.String())
	}
	link := panelLink(t, w.Body.String())
	if st, _ := e.approver("POST", link+"/approve", url.Values{"password": {approve}}, phone); st != http.StatusOK {
		t.Fatalf("approve through the panel link: %d", st)
	}
	got := e.wait(*r.RequestID)
	if got.Status != contract.StatusApproved || got.Value == nil || *got.Value != "pg-secret-1" {
		t.Fatalf("value: %+v", got)
	}
}

// panelLink returns the path of the first approval link in the panel HTML.
func panelLink(t *testing.T, body string) string {
	t.Helper()
	const prefix = "http://100.64.0.1:8787/a/"
	i := strings.Index(body, prefix)
	if i < 0 {
		t.Fatal("no approval link in the panel")
	}
	rest := body[i:]
	if j := strings.IndexAny(rest, `"' <`); j >= 0 {
		rest = rest[:j]
	}
	u, err := url.Parse(rest)
	if err != nil {
		t.Fatal(err)
	}
	return u.Path
}

func TestListenersAreSeparate(t *testing.T) {
	e := newEnv(t)
	e.create("staging-db", "password")
	link := e.ntfy.lastLink(t)
	// The agent listener has no approver routes: it answers with the contract, never a page.
	if r, raw := e.agent("POST", link+"/approve", "password="+approve, e.token); r.Status != contract.StatusRejected || strings.Contains(raw, "html") {
		t.Fatalf("approver route on agent listener: %s", raw)
	}
	// The approver listener has no agent routes.
	if st, _ := e.approver("POST", "/v1/requests", url.Values{}, phone); st != http.StatusNotFound {
		t.Fatalf("agent route on approver listener: %d", st)
	}
	// Callers without a tailnet address are refused.
	if st, _ := e.approver("GET", link, nil, "127.0.0.1:5555"); st != http.StatusForbidden {
		t.Fatalf("loopback caller: %d", st)
	}
	if st, _ := e.approver("GET", link, nil, "192.168.1.5:5555"); st != http.StatusForbidden {
		t.Fatalf("LAN caller: %d", st)
	}
	// A forged link fails.
	if st, _ := e.approver("GET", "/a/r_forged.9999999999.AAAA", nil, phone); st != http.StatusNotFound {
		t.Fatalf("forged link: %d", st)
	}
}
func TestAllowLoopbackIsOptIn(t *testing.T) {
	e := newEnv(t)
	e.create("staging-db", "password")
	link := e.ntfy.lastLink(t)
	if st, _ := e.approver("GET", link, nil, "127.0.0.1:9"); st != http.StatusForbidden {
		t.Fatalf("loopback without demo flag: %d", st)
	}
	e.srv.AllowLoopback = true
	if st, body := e.approver("GET", link, nil, "127.0.0.1:9"); st != http.StatusOK || !strings.Contains(body, "Demo on this machine") {
		t.Fatalf("loopback demo: %d %s", st, body)
	}
	if st, _ := e.approver("GET", link, nil, "[::1]:9"); st != http.StatusOK {
		t.Fatalf("ipv6 loopback: %d", st)
	}
	if st, _ := e.approver("GET", link, nil, "192.168.1.5:9"); st != http.StatusForbidden {
		t.Fatalf("LAN still forbidden: %d", st)
	}
}

func TestRestartForgetsRequests(t *testing.T) {
	e := newEnv(t)
	r := e.create("staging-db", "password")
	e2 := newEnv(t)
	e2.token = e.token
	e2.cfg.Agents = e.cfg.Agents
	if w := e2.wait(*r.RequestID); code(w) != contract.CodeUnknownRequest {
		t.Fatalf("want unknown_request after restart, got %+v", w)
	}
}

func TestPanicGivesContractResponse(t *testing.T) {
	e := newEnv(t)
	e.srv.Vault = nil // any call on the vault panics
	r, _ := e.agent("POST", "/v1/requests", `{"item":"staging-db","field":"password","reason":"x"}`, e.token)
	if code(r) != contract.CodeInternalError {
		t.Fatalf("want internal_error, got %+v", r)
	}
}

func TestAdminCannotRunBW(t *testing.T) {
	e := newEnv(t)
	tok, hash, err := auth.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.Admin.TokenSHA256 = hash
	req := httptest.NewRequest(http.MethodPost, "/admin/bw", strings.NewReader("args=list"))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "broker_admin", Value: tok})
	w := httptest.NewRecorder()
	e.srv.AdminHandler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin bw runner still exists: %d", w.Code)
	}
}
