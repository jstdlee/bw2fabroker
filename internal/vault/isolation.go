package vault

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultAppData returns the Bitwarden CLI data directory: BITWARDENCLI_APPDATA_DIR when it is
// set, otherwise the CLI's own directory under the user's home.
func DefaultAppData() string {
	if d := os.Getenv("BITWARDENCLI_APPDATA_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "Bitwarden CLI")
}

// Isolation describes the state of the Bitwarden CLI data directory.
type Isolation struct {
	Path    string
	Mode    os.FileMode
	Owner   int
	Foreign bool // the directory belongs to another user
}

// Inspect reads the state of the Bitwarden CLI data directory.
func Inspect(appData string) (Isolation, error) {
	dir := appData
	if dir == "" {
		dir = DefaultAppData()
	}
	if dir == "" {
		return Isolation{}, errors.New("the Bitwarden CLI data directory is not known")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return Isolation{Path: dir}, fmt.Errorf("the Bitwarden CLI data directory %s cannot be read: %w", dir, err)
	}
	if !st.IsDir() {
		return Isolation{Path: dir}, fmt.Errorf("%s is not a directory", dir)
	}
	iso := Isolation{Path: dir, Mode: st.Mode().Perm()}
	if sys, ok := statOwner(st); ok {
		iso.Owner = int(sys)
		iso.Foreign = os.Geteuid() != 0 && sys != uint32(os.Geteuid())
	}
	return iso, nil
}

// CheckIsolation returns an error when another user on this host can read the Bitwarden
// session data. The broker must be the only holder of the agents account: a readable
// data directory would let any local user unlock the same account and read the items
// without the broker, and without your approval.
func CheckIsolation(appData string) error {
	iso, err := Inspect(appData)
	if err != nil {
		return err
	}
	if iso.Mode.Perm()&0o077 != 0 {
		return fmt.Errorf("the Bitwarden CLI data directory %s is readable by other users (mode %04o); "+
			"run: chmod 700 %s", iso.Path, iso.Mode.Perm(), iso.Path)
	}
	return nil
}

// CheckBinary returns an error when the bw CLI is missing or not executable.
func CheckBinary(path string) error {
	if path == "" {
		path = "bw"
	}
	resolved := path
	if !filepath.IsAbs(path) {
		p, err := exec.LookPath(path)
		if err != nil {
			return fmt.Errorf("the bw CLI %q was not found on PATH", path)
		}
		resolved = p
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("the bw CLI %s cannot be read: %w", resolved, err)
	}
	if st.IsDir() || st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("the bw CLI %s is not executable", resolved)
	}
	return nil
}

// InContainer reports whether the broker runs inside a container. There the container is
// the isolation boundary, so the host user check does not apply.
func InContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// statOwner reads the owner uid of a file. It is in stat_unix.go on unix and stat_other.go elsewhere.
func statOwner(fi os.FileInfo) (uint32, bool) {
	return ownerUID(fi)
}
