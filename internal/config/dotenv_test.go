package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// freeEnv removes a variable for the rest of the test and restores its original
// value when the test ends.
func freeEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
}

// writeDotEnv writes a .env file in a fresh temporary directory.
func writeDotEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), DotEnvName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDotEnvSimple(t *testing.T) {
	freeEnv(t, "DOTENV_SIMPLE")
	path := writeDotEnv(t, "DOTENV_SIMPLE=hello\n")
	got, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("path %q want %q", got, path)
	}
	if n != 1 {
		t.Fatalf("count %d want 1", n)
	}
	if v := os.Getenv("DOTENV_SIMPLE"); v != "hello" {
		t.Fatalf("value %q want %q", v, "hello")
	}
}

func TestLoadDotEnvExportPrefix(t *testing.T) {
	freeEnv(t, "DOTENV_EXPORT")
	freeEnv(t, "DOTENV_EXPORT_UPPER")
	freeEnv(t, "DOTENV_EXPORT_CASE")
	path := writeDotEnv(t, "export DOTENV_EXPORT=one\nexport   DOTENV_EXPORT_UPPER=two\nEXPORT DOTENV_EXPORT_CASE=three\nexport DOTENV_EXPORT=four\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("count %d want 3", n)
	}
	if v := os.Getenv("DOTENV_EXPORT"); v != "one" {
		t.Fatalf("value %q want %q", v, "one")
	}
	if v := os.Getenv("DOTENV_EXPORT_UPPER"); v != "two" {
		t.Fatalf("value %q want %q", v, "two")
	}
	if v := os.Getenv("DOTENV_EXPORT_CASE"); v != "three" {
		t.Fatalf("value %q want %q", v, "three")
	}
}

func TestLoadDotEnvCommentsAndBlankLines(t *testing.T) {
	freeEnv(t, "DOTENV_AFTER_COMMENT")
	path := writeDotEnv(t, "# a comment\n\n   # an indented comment\n\t\nDOTENV_AFTER_COMMENT=value\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count %d want 1", n)
	}
	if v := os.Getenv("DOTENV_AFTER_COMMENT"); v != "value" {
		t.Fatalf("value %q want %q", v, "value")
	}
}

func TestLoadDotEnvSingleQuotesAreLiteral(t *testing.T) {
	freeEnv(t, "DOTENV_SINGLE")
	path := writeDotEnv(t, `DOTENV_SINGLE='a\nb\tc'`+"\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count %d want 1", n)
	}
	if v := os.Getenv("DOTENV_SINGLE"); v != `a\nb\tc` {
		t.Fatalf("value %q want %q", v, `a\nb\tc`)
	}
}

func TestLoadDotEnvDoubleQuotesAreUnescaped(t *testing.T) {
	freeEnv(t, "DOTENV_DOUBLE")
	path := writeDotEnv(t, `DOTENV_DOUBLE="line1\nline2\ttab"`+"\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count %d want 1", n)
	}
	if v := os.Getenv("DOTENV_DOUBLE"); v != "line1\nline2\ttab" {
		t.Fatalf("value %q", v)
	}
}

func TestLoadDotEnvDoubleQuotesCarriageReturnNewline(t *testing.T) {
	freeEnv(t, "DOTENV_CR")
	path := writeDotEnv(t, `DOTENV_CR="a\r\nb"`+"\n")
	if _, _, err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("DOTENV_CR"); v != "a\nb" {
		t.Fatalf("value %q want %q", v, "a\nb")
	}
}

func TestLoadDotEnvValueWithEquals(t *testing.T) {
	freeEnv(t, "DOTENV_EQUALS")
	path := writeDotEnv(t, "DOTENV_EQUALS=a=b=c\n")
	if _, _, err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("DOTENV_EQUALS"); v != "a=b=c" {
		t.Fatalf("value %q want %q", v, "a=b=c")
	}
}

func TestLoadDotEnvValueWithSpaces(t *testing.T) {
	freeEnv(t, "DOTENV_SPACES")
	path := writeDotEnv(t, "DOTENV_SPACES=   spaced value   \n")
	if _, _, err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("DOTENV_SPACES"); v != "spaced value" {
		t.Fatalf("value %q want %q", v, "spaced value")
	}
}

func TestLoadDotEnvKeepsExistingVariable(t *testing.T) {
	t.Setenv("DOTENV_EXISTING", "original")
	path := writeDotEnv(t, "DOTENV_EXISTING=new\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
	if v := os.Getenv("DOTENV_EXISTING"); v != "original" {
		t.Fatalf("value %q want %q", v, "original")
	}
}

func TestLoadDotEnvKeepsExistingEmptyVariable(t *testing.T) {
	t.Setenv("DOTENV_EMPTY", "")
	path := writeDotEnv(t, "DOTENV_EMPTY=new\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
	if v := os.Getenv("DOTENV_EMPTY"); v != "" {
		t.Fatalf("value %q want empty", v)
	}
}

func TestLoadDotEnvSkipsInvalidKey(t *testing.T) {
	freeEnv(t, "1DOTENV")
	freeEnv(t, "DOTENV-DASH")
	path := writeDotEnv(t, "1DOTENV=one\nDOTENV-DASH=two\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
	if _, ok := os.LookupEnv("1DOTENV"); ok {
		t.Fatal("invalid key was set")
	}
	if _, ok := os.LookupEnv("DOTENV-DASH"); ok {
		t.Fatal("invalid key was set")
	}
}

func TestLoadDotEnvSkipsLineWithoutEquals(t *testing.T) {
	path := writeDotEnv(t, "DOTENV_NO_EQUALS\n")
	_, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
}

func TestLoadDotEnvMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), DotEnvName)
	got, n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("path %q want empty", got)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
}

func TestLoadDotEnvUnreadableFile(t *testing.T) {
	path := writeDotEnv(t, "DOTENV_UNREADABLE=value\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	got, n, err := LoadDotEnv(path)
	if err == nil {
		t.Fatal("unreadable file accepted")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error %v does not wrap fs.ErrPermission", err)
	}
	if got != "" || n != 0 {
		t.Fatalf("path %q count %d", got, n)
	}
}

func TestLoadDotEnvFromPicksFirstDirectory(t *testing.T) {
	freeEnv(t, "DOTENV_FROM")
	empty := t.TempDir()
	full := t.TempDir()
	other := t.TempDir()
	path := filepath.Join(full, DotEnvName)
	if err := os.WriteFile(path, []byte("DOTENV_FROM=first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, DotEnvName), []byte("DOTENV_FROM=second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, n, err := LoadDotEnvFrom(empty, full, other)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("path %q want %q", got, path)
	}
	if n != 1 {
		t.Fatalf("count %d want 1", n)
	}
	if v := os.Getenv("DOTENV_FROM"); v != "first" {
		t.Fatalf("value %q want %q", v, "first")
	}
}

func TestLoadDotEnvFromWithoutDirectories(t *testing.T) {
	got, n, err := LoadDotEnvFrom()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("path %q want empty", got)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
}

func TestLoadDotEnvFromWithoutFile(t *testing.T) {
	got, n, err := LoadDotEnvFrom("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("path %q want empty", got)
	}
	if n != 0 {
		t.Fatalf("count %d want 0", n)
	}
}
