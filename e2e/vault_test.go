//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"github.com/jstdlee/bw2fabroker/internal/api"
	"github.com/jstdlee/bw2fabroker/internal/audit"
	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/config"
	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/notify"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

const (
	e2eEmail    = "bw2fa-e2e@example.com"
	e2ePassword = "e2e-master-password"
	e2eSecret   = "e2e-secret-value"
	e2eItem     = "e2e-item"
	e2eNote     = "e2e-note-value"
	e2eCustom   = "e2e-custom-value"
	e2eURI      = "postgres://db.example.test"
	e2eCard     = "4242424242424242"
	e2eMail     = "ada@e2e.example"
	e2eFileBody = "e2e-attachment-body"
	e2eApprove  = "e2e-approve-password"
	e2eFileName = "e2e.txt"
)

// localClient trusts the test's own loopback certificate. It is not used for any other host.
var localClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

func TestDisposableVault(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("bw"); err != nil {
		t.Fatal(err)
	}
	prod := filepath.Join(os.Getenv("HOME"), ".config", "Bitwarden CLI", "data.json")
	before := fileStamp(prod)

	dir := t.TempDir()
	app := filepath.Join(dir, "bw")
	if err := os.MkdirAll(app, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "vaultwarden")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certGen := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
		"-days", "1", "-nodes", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
	if out, err := certGen.CombinedOutput(); err != nil {
		t.Fatalf("cert: %v\n%s", err, out)
	}
	t.Setenv("NODE_EXTRA_CA_CERTS", certPath)

	name := "bw2fa-e2e-vault"
	_ = exec.Command("docker", "rm", "-f", name).Run()
	run := exec.Command("docker", "run", "-d", "--name", name,
		"-p", "127.0.0.1:18222:443",
		"-e", "SIGNUPS_ALLOWED=true",
		"-e", "WEBSOCKET_ENABLED=false",
		"-e", "ROCKET_PORT=443",
		"-e", `ROCKET_TLS={certs="/certs/cert.pem",key="/certs/key.pem"}`,
		"-v", data+":/data",
		"-v", certPath+":/certs/cert.pem:ro",
		"-v", keyPath+":/certs/key.pem:ro",
		"vaultwarden/server:latest")
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("vaultwarden: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		_ = exec.Command("docker", "run", "--rm", "-v", data+":/data", "--entrypoint", "chown",
			"vaultwarden/server:latest", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "/data").Run()
		if got := fileStamp(prod); got != before {
			t.Errorf("production Bitwarden data changed: %s -> %s", before, got)
		}
	})

	base := "https://127.0.0.1:18222"
	waitAlive(t, base)
	register(t, base)

	bw(t, app, "", "config", "server", base)
	session := strings.TrimSpace(bw(t, app, "", "login", e2eEmail, e2ePassword, "--raw"))
	if session == "" {
		t.Fatal("bw login returned no session")
	}
	loginID := createItem(t, app, session, map[string]any{
		"type":  1,
		"name":  e2eItem,
		"notes": e2eNote,
		"login": map[string]any{
			"username": "app",
			"password": e2eSecret,
			"uris":     []map[string]string{{"uri": e2eURI}},
		},
		"fields": []map[string]any{{"name": "api_key", "value": e2eCustom, "type": 0}},
	})
	cardID := createItem(t, app, session, map[string]any{
		"type": 3,
		"name": "e2e-card",
		"card": map[string]string{
			"cardholderName": "Ada", "brand": "Visa", "number": e2eCard,
			"expMonth": "01", "expYear": "2030", "code": "123",
		},
	})
	idID := createItem(t, app, session, map[string]any{
		"type": 4,
		"name": "e2e-id",
		"identity": map[string]string{
			"firstName": "Ada", "lastName": "Lovelace", "email": e2eMail,
		},
	})
	file := filepath.Join(dir, e2eFileName)
	if err := os.WriteFile(file, []byte(e2eFileBody), 0o600); err != nil {
		t.Fatal(err)
	}
	bw(t, app, session, "create", "attachment", "--file", file, "--itemid", loginID)
	bw(t, app, session, "sync")

	key, err := auth.NewKey(32)
	if err != nil {
		t.Fatal(err)
	}
	tok, hash, err := auth.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	pwHash, err := auth.HashPassword(e2eApprove)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		HMACKey:          key,
		ApprovalPassword: pwHash,
		Agents:           map[string]config.Agent{"e2e": {TokenSHA256: hash}},
		Auto: []config.AutoRule{
			{ItemID: cardID},
			{ItemID: idID},
			{ItemID: loginID, Field: "notes"},
			{ItemID: loginID, Field: "uri"},
			{ItemID: loginID, Field: "custom:api_key"},
			{ItemID: loginID, Field: "attachment:" + e2eFileName},
		},
		Vault: config.Vault{BWPath: "bw", AppData: app},
	}
	cfg.Defaults()
	vw := vault.NewBW("bw", app)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := vw.Unlock(ctx, e2ePassword); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vw.Lock() })

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	linker, err := auth.NewLinker(key)
	if err != nil {
		t.Fatal(err)
	}
	notes := &capNotify{}
	srv := api.New(func() *config.Config { return cfg }, vw, notes, linker, log)
	srv.SetApproverBase("http://100.64.0.1:8787")
	alog, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Audit = alog

	pending := agentCall(t, srv, tok, http.MethodPost, "/v1/requests", `{"item":"`+e2eItem+`","field":"password","reason":"e2e ask path"}`)
	if pending.Status != contract.StatusPending || pending.RequestID == nil {
		t.Fatalf("want pending, got %+v", pending)
	}
	notes.mu.Lock()
	click := notes.click
	notes.mu.Unlock()
	u, err := url.Parse(click)
	if err != nil || u.Path == "" {
		t.Fatalf("approval link: %q", click)
	}
	approve(t, srv, u.Path)
	got := agentCall(t, srv, tok, http.MethodGet, "/v1/requests/"+*pending.RequestID+"/wait", "")
	if got.Status != contract.StatusApproved || got.Value == nil || *got.Value != e2eSecret {
		t.Fatalf("ask path: %+v", got)
	}
	again := agentCall(t, srv, tok, http.MethodGet, "/v1/requests/"+*pending.RequestID+"/wait", "")
	if again.Status != contract.StatusDenied || again.Code == nil || *again.Code != contract.CodeUnknownRequest || again.Value != nil {
		t.Fatalf("value delivered twice: %+v", again)
	}

	auto := map[string]string{
		"notes":                     e2eNote,
		"uri":                       e2eURI,
		"custom:api_key":            e2eCustom,
		"attachment:" + e2eFileName: e2eFileBody,
	}
	for field, value := range auto {
		resp := agentCall(t, srv, tok, http.MethodPost, "/v1/requests", `{"item":"`+e2eItem+`","field":"`+field+`","reason":"e2e field"}`)
		if resp.Status != contract.StatusApproved || resp.Code == nil || *resp.Code != contract.CodeAuto || resp.Value == nil || *resp.Value != value {
			t.Fatalf("%s: %+v", field, resp)
		}
	}
	card := agentCall(t, srv, tok, http.MethodPost, "/v1/requests", `{"item":"e2e-card","field":"card:number","reason":"e2e card"}`)
	if card.Status != contract.StatusApproved || card.Value == nil || *card.Value != e2eCard {
		t.Fatalf("card: %+v", card)
	}
	ident := agentCall(t, srv, tok, http.MethodPost, "/v1/requests", `{"item":"e2e-id","field":"identity:email","reason":"e2e identity"}`)
	if ident.Status != contract.StatusApproved || ident.Value == nil || *ident.Value != e2eMail {
		t.Fatalf("identity: %+v", ident)
	}

	logged, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	blob := string(logged) + logBuf.String()
	for _, secret := range []string{e2eSecret, e2ePassword, e2eApprove, e2eNote, e2eCustom, e2eCard, e2eMail, e2eFileBody} {
		if strings.Contains(blob, secret) {
			t.Fatalf("audit or log contains %q", secret)
		}
	}
}

type capNotify struct {
	mu    sync.Mutex
	click string
}

func (c *capNotify) Send(_ context.Context, m notify.Message) error {
	c.mu.Lock()
	c.click = m.Click
	c.mu.Unlock()
	return nil
}

func createItem(t *testing.T, app, session string, item any) string {
	t.Helper()
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	out := bw(t, app, session, "create", "item", base64.StdEncoding.EncodeToString(raw))
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &created); err != nil || created.ID == "" {
		t.Fatalf("create item: %s", out)
	}
	return created.ID
}

func agentCall(t *testing.T, srv *api.Server, tok, method, path, body string) contract.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	srv.AgentHandler().ServeHTTP(w, req)
	var resp contract.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %s", w.Body.String())
	}
	if err := resp.Valid(); err != nil {
		t.Fatalf("invalid response %s: %v", w.Body.String(), err)
	}
	return resp
}

func approve(t *testing.T, srv *api.Server, linkPath string) {
	t.Helper()
	form := url.Values{"password": {e2eApprove}}
	req := httptest.NewRequest(http.MethodPost, linkPath+"/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "100.70.1.2:51000"
	w := httptest.NewRecorder()
	srv.ApproverHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Approved") {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
}

func waitAlive(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := localClient.Get(base + "/alive")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("vaultwarden did not start: %v", last)
}

func register(t *testing.T, base string) {
	t.Helper()
	master := pbkdf2.Key([]byte(e2ePassword), []byte(e2eEmail), 600000, 32, sha256.New)
	hash := pbkdf2.Key(master, []byte(e2ePassword), 1, 32, sha256.New)
	encKey := hkdfExpand(master, "enc")
	macKey := hkdfExpand(master, "mac")
	userKey := make([]byte, 64)
	if _, err := rand.Read(userKey); err != nil {
		t.Fatal(err)
	}
	tokenCode, tokenBody := postJSON(t, base+"/identity/accounts/register/send-verification-email", map[string]string{
		"email": e2eEmail,
		"name":  "e2e",
	})
	if tokenCode != http.StatusOK {
		t.Fatalf("verification token %d: %s", tokenCode, tokenBody)
	}
	var token string
	if err := json.Unmarshal(tokenBody, &token); err != nil || token == "" {
		t.Fatalf("verification token: %s", tokenBody)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	kdf := map[string]any{"kdfType": 0, "iterations": 600000}
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	code, msg := postJSON(t, base+"/identity/accounts/register/finish", map[string]any{
		"email":                  e2eEmail,
		"emailVerificationToken": token,
		"userAsymmetricKeys": map[string]string{
			"publicKey":           base64.StdEncoding.EncodeToString(pub),
			"encryptedPrivateKey": encrypt(userKey[:32], userKey[32:], priv),
		},
		"masterPasswordAuthentication": map[string]any{
			"kdf":                              kdf,
			"salt":                             e2eEmail,
			"masterPasswordAuthenticationHash": hashB64,
		},
		"masterPasswordUnlock": map[string]any{
			"kdf":                     kdf,
			"salt":                    e2eEmail,
			"masterKeyWrappedUserKey": encrypt(encKey, macKey, userKey),
		},
	})
	if code != http.StatusOK {
		t.Fatalf("register %d: %s", code, msg)
	}
}

func postJSON(t *testing.T, url string, payload any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := localClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, msg
}

func hkdfExpand(prk []byte, info string) []byte {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func encrypt(encKey, macKey, plain []byte) string {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}
	padded := pkcs7(plain, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	m := hmac.New(sha256.New, macKey)
	m.Write(iv)
	m.Write(ct)
	b64 := base64.StdEncoding.EncodeToString
	return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(m.Sum(nil))
}

func pkcs7(b []byte, n int) []byte {
	pad := n - len(b)%n
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func bw(t *testing.T, app, session string, args ...string) string {
	t.Helper()
	cmd := exec.Command("bw", args...)
	cmd.Env = cleanEnv(app, session)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bw %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func cleanEnv(app, session string) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "BITWARDENCLI_APPDATA_DIR", "BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD", "BW_MASTER_PASSWORD":
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "BITWARDENCLI_APPDATA_DIR="+app, "NODE_NO_WARNINGS=1")
	if session != "" {
		out = append(out, "BW_SESSION="+session)
	}
	return out
}

func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "absent"
	}
	return st.ModTime().UTC().Format(time.RFC3339Nano) + "/" + fmt.Sprint(st.Size())
}
