// Package vault reads single fields from Bitwarden through the `bw` CLI. BW_SESSION lives only in
// this process's memory and in the environment of each short-lived `bw` child.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

// Item is what the approval page shows. It never holds secret values.
type Item struct {
	ID     string
	Name   string
	Folder string
}

// CatalogItem is one item as list and search return it. Fields are names only.
type CatalogItem struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Folder string   `json:"folder"`
	Fields []string `json:"fields"`
}

// Errors.
var (
	ErrUnknownItem   = errors.New("unknown item")
	ErrAmbiguousItem = errors.New("ambiguous item")
	ErrNoField       = errors.New("field not present on item")
	ErrLocked        = errors.New("vault locked")
)

// Vault is the interface the broker uses.
type Vault interface {
	Unlocked() bool
	Unlock(ctx context.Context, masterPassword string) error
	Resolve(ctx context.Context, item string) (Item, error)
	// HasField checks that the field exists without returning its value.
	HasField(ctx context.Context, itemID string, f contract.Field) error
	Read(ctx context.Context, itemID string, f contract.Field) (string, error)
	// Search and List return names and field names. They do not return values.
	Search(ctx context.Context, query string) ([]CatalogItem, error)
	List(ctx context.Context) ([]CatalogItem, error)
	Sync(ctx context.Context) error
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsID reports whether s looks like a Bitwarden item id.
func IsID(s string) bool { return uuidRe.MatchString(s) }

// BW runs the bw CLI.
type BW struct {
	Path    string
	AppData string

	mu      sync.RWMutex
	session string
	folders map[string]string
}

// NewBW returns a bw adapter.
func NewBW(path, appData string) *BW { return &BW{Path: path, AppData: appData} }

// Unlocked reports whether a session key is held.
func (b *BW) Unlocked() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.session != ""
}

func (b *BW) baseEnv(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "NODE_NO_WARNINGS=1"}
	if b.AppData != "" {
		env = append(env, "BITWARDENCLI_APPDATA_DIR="+b.AppData)
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

func (b *BW) env(extra ...string) []string {
	return append(b.baseEnv(), append([]string{"BW_NOINTERACTION=true"}, extra...)...)
}

// Login runs `bw login` against the broker's profile, attached to the caller's terminal, because
// bw asks for the master password and any two-step code itself. With an API key the client id and
// secret go in the child's environment, so neither appears in argv. The login state goes to the
// profile directory; the broker never reads a session from its own environment.
func (b *BW) Login(ctx context.Context, apikey bool, clientID, clientSecret, email string) error {
	args := []string{"login"}
	var env []string
	switch {
	case apikey && clientID != "" && clientSecret != "":
		args = append(args, "--apikey")
		env = append(env, "BW_CLIENTID="+clientID, "BW_CLIENTSECRET="+clientSecret)
	case apikey:
		args = append(args, "--apikey")
	case email != "":
		args = append(args, email)
	}
	cmd := exec.CommandContext(ctx, b.Path, args...)
	cmd.Env = b.baseEnv(env...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bw login: %w", err)
	}
	return nil
}

func (b *BW) run(ctx context.Context, withSession bool, extraEnv []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	env := extraEnv
	if withSession {
		b.mu.RLock()
		s := b.session
		b.mu.RUnlock()
		if s == "" {
			return nil, ErrLocked
		}
		env = append(env, "BW_SESSION="+s)
	}
	cmd := exec.CommandContext(ctx, b.Path, append(args, "--nointeraction")...)
	cmd.Env = b.env(env...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if strings.Contains(strings.ToLower(msg), "not found") {
			return nil, ErrUnknownItem
		}
		if strings.Contains(msg, "More than one result") {
			return nil, ErrAmbiguousItem
		}
		// Keep stderr short; it never holds secret values.
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("bw %s: %v: %s", args[0], err, msg)
	}
	return out.Bytes(), nil
}

// Status returns `bw status` (unauthenticated, locked, unlocked).
func (b *BW) Status(ctx context.Context) (string, error) {
	out, err := b.run(ctx, b.Unlocked(), nil, "status")
	if err != nil {
		return "", err
	}
	var s struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return "", err
	}
	return s.Status, nil
}

// Account returns the email of the logged-in user, or "" when bw reports none. Doctor prints it
// because the whole isolation rests on this being the agents account, not a personal one.
func (b *BW) Account(ctx context.Context) (string, error) {
	out, err := b.run(ctx, b.Unlocked(), nil, "status")
	if err != nil {
		return "", err
	}
	var s struct {
		UserEmail string `json:"userEmail"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return "", err
	}
	return s.UserEmail, nil
}

// Unlock runs `bw unlock --raw` with the password in the child's environment only.
func (b *BW) Unlock(ctx context.Context, master string) error {
	out, err := b.run(ctx, false, []string{"BW2FA_MASTER=" + master}, "unlock", "--raw", "--passwordenv", "BW2FA_MASTER")
	if err != nil {
		return errors.New("bw unlock failed: wrong master password, or `broker login` was not run for this profile")
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return errors.New("bw unlock returned no session")
	}
	b.mu.Lock()
	b.session = s
	b.mu.Unlock()
	return b.Sync(ctx)
}

// Lock forgets the session key.
func (b *BW) Lock() {
	b.mu.Lock()
	b.session = ""
	b.mu.Unlock()
}

// Sync runs `bw sync` and refreshes folder names.
func (b *BW) Sync(ctx context.Context) error {
	if _, err := b.run(ctx, true, nil, "sync"); err != nil {
		return err
	}
	out, err := b.run(ctx, true, nil, "list", "folders")
	if err != nil {
		return err
	}
	var fs []struct {
		ID   *string `json:"id"`
		Name string  `json:"name"`
	}
	if err := json.Unmarshal(out, &fs); err != nil {
		return err
	}
	m := map[string]string{}
	for _, f := range fs {
		if f.ID != nil {
			m[*f.ID] = f.Name
		}
	}
	b.mu.Lock()
	b.folders = m
	b.mu.Unlock()
	return nil
}

type bwItem struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Notes       *string        `json:"notes"`
	FolderID    *string        `json:"folderId"`
	Login       *bwLogin       `json:"login"`
	Card        *bwCard        `json:"card"`
	Identity    *bwIdentity    `json:"identity"`
	Fields      []bwField      `json:"fields"`
	Attachments []bwAttachment `json:"attachments"`
}

func (b *BW) toItem(it bwItem) Item {
	folder := ""
	if it.FolderID != nil {
		b.mu.RLock()
		folder = b.folders[*it.FolderID]
		b.mu.RUnlock()
	}
	return Item{ID: it.ID, Name: it.Name, Folder: folder}
}

// Resolve finds exactly one item by id or by exact name.
func (b *BW) Resolve(ctx context.Context, item string) (Item, error) {
	if IsID(item) {
		it, err := b.getItem(ctx, item)
		if err != nil {
			return Item{}, err
		}
		return b.toItem(it), nil
	}
	out, err := b.run(ctx, true, nil, "list", "items", "--search", item)
	if err != nil {
		return Item{}, err
	}
	var items []bwItem
	if err := json.Unmarshal(out, &items); err != nil {
		return Item{}, err
	}
	var match []bwItem
	for _, it := range items {
		if it.Name == item {
			match = append(match, it)
		}
	}
	switch len(match) {
	case 0:
		return Item{}, ErrUnknownItem
	case 1:
		return b.toItem(match[0]), nil
	}
	return Item{}, ErrAmbiguousItem
}

func (b *BW) getItem(ctx context.Context, id string) (bwItem, error) {
	if !IsID(id) {
		return bwItem{}, ErrUnknownItem
	}
	out, err := b.run(ctx, true, nil, "get", "item", id)
	if err != nil {
		return bwItem{}, err
	}
	var it bwItem
	if err := json.Unmarshal(out, &it); err != nil {
		return bwItem{}, err
	}
	if it.ID != id {
		return bwItem{}, ErrUnknownItem
	}
	return it, nil
}

// HasField checks that the item has the field. The value is read and dropped at once.
func (b *BW) HasField(ctx context.Context, itemID string, f contract.Field) error {
	it, err := b.getItem(ctx, itemID)
	if err != nil {
		return err
	}
	if f.Kind == "totp" {
		if it.Login == nil || it.Login.Totp == nil || *it.Login.Totp == "" {
			return ErrNoField
		}
		return nil
	}
	if f.Kind == "attachment" {
		if namedAttachment(it, f.Custom) {
			return nil
		}
		return ErrNoField
	}
	_, err = pickField(it, f)
	return err
}

// Read returns one field of one item.
func (b *BW) Read(ctx context.Context, itemID string, f contract.Field) (string, error) {
	switch f.Kind {
	case "totp":
		if !IsID(itemID) {
			return "", ErrUnknownItem
		}
		out, err := b.run(ctx, true, nil, "get", "totp", itemID)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	case "attachment":
		return b.readAttachment(ctx, itemID, f.Custom)
	}
	it, err := b.getItem(ctx, itemID)
	if err != nil {
		return "", err
	}
	return pickField(it, f)
}

func pickField(it bwItem, f contract.Field) (string, error) {
	deref := func(p *string) (string, error) {
		if p == nil || *p == "" {
			return "", ErrNoField
		}
		return *p, nil
	}
	switch f.Kind {
	case "username":
		if it.Login == nil {
			return "", ErrNoField
		}
		return deref(it.Login.Username)
	case "password":
		if it.Login == nil {
			return "", ErrNoField
		}
		return deref(it.Login.Password)
	case "uri":
		if it.Login == nil || len(it.Login.Uris) == 0 {
			return "", ErrNoField
		}
		return deref(it.Login.Uris[0].URI)
	case "notes":
		return deref(it.Notes)
	case "custom":
		var found []string
		for _, fl := range it.Fields {
			if fl.Name != nil && *fl.Name == f.Custom && fl.Value != nil && fl.Type != 3 { // 3 = linked field
				found = append(found, *fl.Value)
			}
		}
		if len(found) != 1 {
			return "", ErrNoField
		}
		return found[0], nil
	case "card":
		return cardField(it.Card, f.Custom)
	case "identity":
		return identityField(it.Identity, f.Custom)
	}
	return "", ErrNoField
}
