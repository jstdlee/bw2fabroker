// Package notify sends pushes to a self-hosted ntfy server. It refuses any URL that is not https on
// the configured own domain, refuses ntfy.sh, and never follows redirects.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Action is one ntfy button. View opens the approval page. HTTP is the callback that
// refuses to approve without the approval password.
type Action struct {
	Action string // "view" or "http"
	Label  string
	URL    string
	Method string
}

// Message is one push.
type Message struct {
	Title    string
	Body     string
	Click    string // approval link
	Priority int    // 1-5
	Tags     []string
	Actions  []Action
}

// Notifier sends a push.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// ErrPublicChannel means the topic accepted a request with no bearer token.
var ErrPublicChannel = errors.New("ntfy topic accepts requests without bearer authentication")

var topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// CheckOwnDomain validates the own-domain setting itself.
func CheckOwnDomain(domain string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return errors.New("ntfy own domain is not set")
	}
	if d != domain {
		return errors.New("ntfy own domain must be lower case with no spaces")
	}
	if strings.ContainsAny(d, "/:@ ") {
		return errors.New("ntfy own domain must be a host name only, without scheme, port, or path")
	}
	if isPublicNtfy(d) {
		return errors.New("ntfy own domain must not be ntfy.sh; use your self-hosted server")
	}
	return nil
}

func isPublicNtfy(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "ntfy.sh" || strings.HasSuffix(host, ".ntfy.sh")
}

// CheckURL enforces: https, host equal to the own domain, never ntfy.sh, no credentials, no query.
func CheckURL(raw, ownDomain string) (*url.URL, error) {
	if err := CheckOwnDomain(ownDomain); err != nil {
		return nil, err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ntfy url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("ntfy url must use https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("ntfy url must not contain credentials, a query, or a fragment")
	}
	host := strings.ToLower(u.Hostname())
	if isPublicNtfy(host) {
		return nil, errors.New("ntfy url must not be ntfy.sh; use your own domain")
	}
	if host != ownDomain {
		return nil, fmt.Errorf("ntfy url host %q is not the own domain %q", host, ownDomain)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("ntfy url must be the server root, e.g. https://ntfy.example.com")
	}
	u.Path = "/"
	return u, nil
}

// CheckTopic validates a topic name.
func CheckTopic(t string) error {
	if !topicRe.MatchString(t) {
		return errors.New("ntfy topic must be 1-64 characters of A-Z a-z 0-9 _ -")
	}
	return nil
}

// Ntfy is the real client.
type Ntfy struct {
	URL       string
	OwnDomain string
	Topic     string
	Token     string
	Client    *http.Client
}

// New builds an ntfy client. A bearer token is required.
func New(rawURL, ownDomain, topic, token string) (*Ntfy, error) {
	if _, err := CheckURL(rawURL, ownDomain); err != nil {
		return nil, err
	}
	if err := CheckTopic(topic); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("ntfy bearer token is required")
	}
	return &Ntfy{URL: rawURL, OwnDomain: ownDomain, Topic: topic, Token: strings.TrimSpace(token), Client: NewHTTPClient()}, nil
}

// NewHTTPClient returns a client that never follows redirects.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

type actionBody struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Method string `json:"method,omitempty"`
}

type publish struct {
	Topic    string       `json:"topic"`
	Title    string       `json:"title,omitempty"`
	Message  string       `json:"message"`
	Click    string       `json:"click,omitempty"`
	Priority int          `json:"priority,omitempty"`
	Tags     []string     `json:"tags,omitempty"`
	Actions  []actionBody `json:"actions,omitempty"`
}

// Send checks the URL again, then posts the message. Redirects count as failure.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	u, err := CheckURL(n.URL, n.OwnDomain)
	if err != nil {
		return err
	}
	var actions []actionBody
	for _, a := range m.Actions {
		actions = append(actions, actionBody{Action: a.Action, Label: a.Label, URL: a.URL, Method: a.Method})
	}
	body, err := json.Marshal(publish{Topic: n.Topic, Title: m.Title, Message: m.Body, Click: m.Click, Priority: m.Priority, Tags: m.Tags, Actions: actions})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := n.Client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("ntfy answered with a redirect (%d); redirects are not followed", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ntfy answered %d", resp.StatusCode)
	}
	return nil
}

// RequireAuth rejects a topic that can be published to or read without a bearer token.
func (n *Ntfy) RequireAuth(ctx context.Context) error {
	if strings.TrimSpace(n.Token) == "" {
		return errors.New("ntfy bearer token is required")
	}
	u, err := CheckURL(n.URL, n.OwnDomain)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(publish{Topic: n.Topic, Title: "bw2fabroker auth probe", Message: "This server accepted a publish with no bearer token. The broker will not use it."})
	if err := n.probe(ctx, http.MethodPost, u.String(), body); err != nil {
		return err
	}
	sub := strings.TrimRight(u.String(), "/") + "/" + n.Topic + "/json?poll=1&since=1s"
	return n.probe(ctx, http.MethodGet, sub, nil)
}

func (n *Ntfy) probe(ctx context.Context, method, raw string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, raw, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy auth probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return ErrPublicChannel
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil
	}
	return fmt.Errorf("ntfy auth probe returned %d", resp.StatusCode)
}
