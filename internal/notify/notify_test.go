package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	n2, _ := New(redir.URL, ru.Hostname(), "approvals", "")
	n2.Client.Transport = redir.Client().Transport
	if err := n2.Send(context.Background(), Message{Body: "x"}); err == nil {
		t.Fatal("redirect was followed or accepted")
	}
}
