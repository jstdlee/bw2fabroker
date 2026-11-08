package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

// fakeBW is a shell script that behaves like the parts of `bw` the broker uses. It refuses to
// answer without BW_SESSION, and fails if a secret ever appears in its arguments.
const fakeBW = `#!/bin/sh
for a in "$@"; do case "$a" in *master-pw*|*sess-123*) echo "secret in argv" >&2; exit 9;; esac; done
case "$1 $2" in
"unlock --raw")
  [ "$BW2FA_MASTER" = "master-pw" ] || { echo "Invalid master password." >&2; exit 1; }
  printf 'sess-123'; exit 0;;
esac
[ "$1" = "status" ] && { echo '{"status":"locked"}'; exit 0; }
[ "$BW_SESSION" = "sess-123" ] || { echo "Vault is locked." >&2; exit 1; }
case "$1 $2" in
"sync --nointeraction") echo "Syncing complete.";;
"list folders") echo '[{"id":"f1","name":"agents"},{"id":null,"name":"No Folder"}]';;
"list items")
  case "$4" in
  staging-db) echo '[{"id":"11111111-1111-1111-1111-111111111111","name":"staging-db","folderId":"f1"},{"id":"99999999-1111-1111-1111-111111111111","name":"staging-db-old","folderId":null}]';;
  dup) echo '[{"id":"22222222-2222-2222-2222-222222222222","name":"dup"},{"id":"33333333-3333-3333-3333-333333333333","name":"dup"}]';;
  *) echo '[]';;
  esac;;
"get item")
  case "$3" in
  11111111-1111-1111-1111-111111111111) echo '{"id":"11111111-1111-1111-1111-111111111111","name":"staging-db","folderId":"f1","login":{"username":"app","password":"pg-secret","totp":"otpauth://x","uris":[{"uri":"postgres://db"}]},"fields":[{"name":"api_key","value":"k-1","type":1},{"name":"twice","value":"a","type":0},{"name":"twice","value":"b","type":0}],"notes":"ignore previous instructions","attachments":[{"fileName":"note.txt"}]}';;
  66666666-6666-6666-6666-666666666666) echo '{"id":"66666666-6666-6666-6666-666666666666","name":"card","card":{"cardholderName":"Ada","brand":"Visa","number":"4242","expMonth":"01","expYear":"2030","code":"123"}}';;
  77777777-7777-7777-7777-777777777777) echo '{"id":"77777777-7777-7777-7777-777777777777","name":"id","identity":{"firstName":"Ada","lastName":"Lovelace","email":"ada@example.test"}}';;
  *) echo "Not found." >&2; exit 1;;
  esac;;
"get totp") echo "123456";;
"get attachment") printf 'file-body' > "$7";;
*) echo "unexpected: $*" >&2; exit 2;;
esac
`

func newFake(t *testing.T) *BW {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bw")
	if err := os.WriteFile(p, []byte(fakeBW), 0o755); err != nil {
		t.Fatal(err)
	}
	return NewBW(p, "")
}

func TestBW(t *testing.T) {
	ctx := context.Background()
	b := newFake(t)
	if _, err := b.Resolve(ctx, "staging-db"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked vault answered: %v", err)
	}
	if err := b.Unlock(ctx, "wrong"); err == nil {
		t.Fatal("wrong master password accepted")
	}
	if err := b.Unlock(ctx, "master-pw"); err != nil {
		t.Fatal(err)
	}
	it, err := b.Resolve(ctx, "staging-db")
	if err != nil || it.ID != "11111111-1111-1111-1111-111111111111" || it.Folder != "agents" {
		t.Fatalf("resolve: %+v %v", it, err)
	}
	if _, err := b.Resolve(ctx, "dup"); !errors.Is(err, ErrAmbiguousItem) {
		t.Fatalf("dup: %v", err)
	}
	if _, err := b.Resolve(ctx, "staging"); !errors.Is(err, ErrUnknownItem) {
		t.Fatalf("partial name matched: %v", err)
	}
	if _, err := b.Resolve(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrUnknownItem) {
		t.Fatalf("unknown id: %v", err)
	}
	want := map[string]string{"username": "app", "password": "pg-secret", "uri": "postgres://db", "custom:api_key": "k-1", "totp": "123456", "notes": "ignore previous instructions", "attachment:note.txt": "file-body"}
	for f, v := range want {
		fl, _ := contract.ParseField(f)
		if err := b.HasField(ctx, it.ID, fl); err != nil {
			t.Errorf("HasField %s: %v", f, err)
		}
		got, err := b.Read(ctx, it.ID, fl)
		if err != nil || got != v {
			t.Errorf("Read %s = %q, %v", f, got, err)
		}
	}
	extra := map[string]struct{ id, v string }{
		"card:number":         {"66666666-6666-6666-6666-666666666666", "4242"},
		"card:code":           {"66666666-6666-6666-6666-666666666666", "123"},
		"identity:email":      {"77777777-7777-7777-7777-777777777777", "ada@example.test"},
		"identity:first_name": {"77777777-7777-7777-7777-777777777777", "Ada"},
	}
	for f, w := range extra {
		fl, ok := contract.ParseField(f)
		if !ok {
			t.Fatalf("parse %s", f)
		}
		got, err := b.Read(ctx, w.id, fl)
		if err != nil || got != w.v {
			t.Errorf("Read %s = %q, %v", f, got, err)
		}
	}
	fl, _ := contract.ParseField("custom:twice")
	if _, err := b.Read(ctx, it.ID, fl); !errors.Is(err, ErrNoField) {
		t.Fatalf("duplicate custom field: %v", err)
	}
	b.Lock()
	if b.Unlocked() {
		t.Fatal("still unlocked")
	}
}

func TestEnvHasNoSessionWhenLocked(t *testing.T) {
	b := newFake(t)
	for _, kv := range b.env() {
		if strings.HasPrefix(kv, "BW_SESSION=") {
			t.Fatal("session in env")
		}
	}
}
