package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCheckURL(t *testing.T) {
	own := "ntfy.example.com"
	good := []string{"https://ntfy.example.com", "https://ntfy.example.com/", "https://ntfy.example.com:8443"}
	bad := []string{
		"http://ntfy.example.com",
		"https://ntfy.sh",
		"https://x.ntfy.sh",
		"https://other.example.com",
		"https://ntfy.example.com.evil.net",
		"https://user:pw@ntfy.example.com",
		"https://ntfy.example.com/topic",
		"https://ntfy.example.com/?x=1",
		"ntfy.example.com",
	}
	for _, u := range good {
		if _, err := CheckURL(u, own); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := CheckURL(u, own); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, d := range []string{"ntfy.sh", "a.ntfy.sh", "", "https://x", "Ntfy.Example.com"} {
		if CheckOwnDomain(d) == nil {
			t.Errorf("own domain %q accepted", d)
		}
	}
}

func TestSendAndNoRedirect(t *testing.T) {
	var got publish
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-me" {
			return
		}
		if r.Header.Get("Authorization") != "Bearer tk" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n, err := New(srv.URL, u.Hostname(), "approvals", "tk")
	if err != nil {
		t.Fatal(err)
	}
	n.Client.Transport = srv.Client().Transport
	if err := n.Send(context.Background(), Message{Title: "t", Body: "b", Click: "http://100.64.0.1:8787/a/x"}); err != nil {
		t.Fatal(err)
	}
	if got.Topic != "approvals" || got.Click == "" {
		t.Fatalf("bad publish %+v", got)
	}

	// A server that redirects (for example to ntfy.sh) is treated as a failure.
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://ntfy.sh/", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	ru, _ := url.Parse(redir.URL)
	n2, _ := New(redir.URL, ru.Hostname(), "approvals", "tk")
	n2.Client.Transport = redir.Client().Transport
	if err := n2.Send(context.Background(), Message{Body: "x"}); err == nil {
		t.Fatal("redirect was followed or accepted")
	}
}

func TestFromConfig(t *testing.T) {
	if n, err := FromConfig("", "", "", ""); err != nil || n != nil {
		t.Fatalf("empty config: %v %v", n, err)
	}
	partial := [][4]string{
		{"https://ntfy.example.com", "", "", ""},
		{"", "ntfy.example.com", "", ""},
		{"", "", "approvals", ""},
		{"", "", "", "tk"},
		{"https://ntfy.example.com", "ntfy.example.com", "approvals", ""},
		{"https://ntfy.example.com", "ntfy.example.com", "", "tk"},
		{"", "ntfy.example.com", "approvals", "tk"},
	}
	for _, c := range partial {
		if n, err := FromConfig(c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("partial config %q accepted: %v", c, n)
		}
	}
	n, err := FromConfig("https://ntfy.example.com", "ntfy.example.com", "approvals", "tk")
	if err != nil || n == nil || n.Token != "tk" {
		t.Fatalf("full config: %v %v", n, err)
	}
}

// TestRequireAuthProbeBody checks the authed publish the RequireAuth probe sends with the
// configured token: it must ask the server to keep the message off Firebase, and must not
// carry the old "No action needed" wording, so a passing check never rings the phone.
func TestRequireAuthProbeBody(t *testing.T) {
	var authedBody json.RawMessage
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		// The anonymous publish probe arrives first and unauthenticated; the authed publish
		// carries the bearer token, which is the one this test is about.
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authedBody = b
		w.WriteHeader(http.StatusForbidden) // the token is not accepted
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n, err := New(srv.URL, u.Hostname(), "approvals", "tk")
	if err != nil {
		t.Fatal(err)
	}
	n.Client.Transport = srv.Client().Transport
	err = n.RequireAuth(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bearer token") {
		t.Fatalf("unexpected outcome: %v", err)
	}
	if authedBody == nil {
		t.Fatal("the authed probe never reached the server")
	}
	var p publish
	if err := json.Unmarshal(authedBody, &p); err != nil {
		t.Fatal(err)
	}
	if p.Firebase != "no" {
		t.Fatalf("authed probe body %s does not keep the message off Firebase", authedBody)
	}
	if p.Priority != 1 {
		t.Fatalf("authed probe priority = %d, want 1", p.Priority)
	}
	if p.Title != "bw2fabroker probe" {
		t.Fatalf("authed probe title = %q", p.Title)
	}
	if strings.Contains(p.Message, "No action needed") {
		t.Fatalf("authed probe still promises nothing is needed: %q", p.Message)
	}
}

func TestRequireAuthChecksTheToken(t *testing.T) {
	var probeHdr http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		probeHdr = r.Header.Clone()
		w.WriteHeader(http.StatusForbidden) // the token is not accepted
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n, err := New(srv.URL, u.Hostname(), "approvals", "tk")
	if err != nil {
		t.Fatal(err)
	}
	n.Client.Transport = srv.Client().Transport
	err = n.RequireAuth(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bearer token") {
		t.Fatalf("bad token accepted: %v", err)
	}
	if probeHdr.Get("X-Cache") != "no" || probeHdr.Get("X-Firebase-No") != "true" {
		t.Fatalf("probe would leave a message behind: %v", probeHdr)
	}
}

func TestRejectPublicChannel(t *testing.T) {
	pub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer pub.Close()
	u, _ := url.Parse(pub.URL)
	n, err := New(pub.URL, u.Hostname(), "approvals", "tk")
	if err != nil {
		t.Fatal(err)
	}
	n.Client.Transport = pub.Client().Transport
	if err := n.RequireAuth(context.Background()); !errors.Is(err, ErrPublicChannel) {
		t.Fatal(err)
	}
	priv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}))
	defer priv.Close()
	pu, _ := url.Parse(priv.URL)
	n, _ = New(priv.URL, pu.Hostname(), "approvals", "tk")
	n.Client.Transport = priv.Client().Transport
	if err := n.RequireAuth(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCanRead(t *testing.T) {
	for _, c := range []struct {
		name string
		code int
		want bool
	}{
		{"write-only token", http.StatusForbidden, false},
		{"read-write token", http.StatusOK, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var auth string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth = r.Header.Get("Authorization")
				if r.URL.Path != "/approvals/json" || r.URL.Query().Get("poll") != "1" {
					t.Errorf("probe hit %s", r.URL)
				}
				w.WriteHeader(c.code)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			n, err := New(srv.URL, u.Hostname(), "approvals", "tk")
			if err != nil {
				t.Fatal(err)
			}
			n.Client.Transport = srv.Client().Transport
			got, err := n.CanRead(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("CanRead = %v, want %v", got, c.want)
			}
			if auth != "Bearer tk" {
				t.Fatalf("probe sent %q", auth)
			}
		})
	}
}
