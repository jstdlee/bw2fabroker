// Package vaulttest has an in-memory vault for tests.
package vaulttest

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// Item is one fake item.
type Item struct {
	ID, Name, Folder string
	Fields           map[string]string // username, password, totp, uri, custom:<name>
}

// Fake is an in-memory vault.
type Fake struct {
	mu      sync.Mutex
	Items   []Item
	Locked  bool
	Master  string
	Reads   int
	ReadErr error
}

func (f *Fake) Unlocked() bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.Locked }

func (f *Fake) Unlock(_ context.Context, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pw != f.Master {
		return vault.ErrLocked
	}
	f.Locked = false
	return nil
}

func (f *Fake) Sync(context.Context) error { return nil }

func (f *Fake) find(item string) ([]Item, error) {
	if f.Locked {
		return nil, vault.ErrLocked
	}
	var out []Item
	for _, it := range f.Items {
		if it.ID == item || (!vault.IsID(item) && it.Name == item) {
			out = append(out, it)
		}
	}
	return out, nil
}

func (f *Fake) Resolve(_ context.Context, item string) (vault.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.find(item)
	if err != nil {
		return vault.Item{}, err
	}
	switch len(m) {
	case 0:
		return vault.Item{}, vault.ErrUnknownItem
	case 1:
		return vault.Item{ID: m[0].ID, Name: m[0].Name, Folder: m[0].Folder}, nil
	}
	return vault.Item{}, vault.ErrAmbiguousItem
}

func (f *Fake) value(id string, fl contract.Field) (string, error) {
	m, err := f.find(id)
	if err != nil {
		return "", err
	}
	if len(m) != 1 {
		return "", vault.ErrUnknownItem
	}
	v, ok := m[0].Fields[fl.String()]
	if !ok {
		return "", vault.ErrNoField
	}
	return v, nil
}

func (f *Fake) HasField(_ context.Context, id string, fl contract.Field) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.value(id, fl)
	return err
}

func (f *Fake) Read(_ context.Context, id string, fl contract.Field) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Reads++
	if f.ReadErr != nil {
		return "", f.ReadErr
	}
	return f.value(id, fl)
}

func (f *Fake) Search(_ context.Context, query string) ([]vault.CatalogItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Locked {
		return nil, vault.ErrLocked
	}
	q := strings.ToLower(query)
	var out []vault.CatalogItem
	for _, it := range f.Items {
		if q != "" && !strings.Contains(strings.ToLower(it.Name), q) {
			continue
		}
		var fields []string
		for k, v := range it.Fields {
			if v != "" {
				fields = append(fields, k)
			}
		}
		sort.Strings(fields)
		out = append(out, vault.CatalogItem{ID: it.ID, Name: it.Name, Folder: it.Folder, Fields: fields})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) List(ctx context.Context) ([]vault.CatalogItem, error) {
	return f.Search(ctx, "")
}

func (f *Fake) Exec(_ context.Context, args []string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(args) == 0 {
		return "", "bw needs arguments", vault.ErrLocked
	}
	if args[0] != "status" && f.Locked {
		return "", "locked", vault.ErrLocked
	}
	return "ok " + strings.Join(args, " "), "", nil
}
