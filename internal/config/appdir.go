package config

import (
	"os"
	"path/filepath"
	"strings"
)

// AppDirs returns the directories to search for a .env file, most specific first.
// BROKER_APP_DIR wins when it is set. Then the directory that holds the config file,
// then the directory of the running binary, then the working directory.
func AppDirs() []string {
	dirs := make([]string, 0, 4)
	if d := strings.TrimSpace(os.Getenv("BROKER_APP_DIR")); d != "" {
		dirs = append(dirs, d)
	}
	dirs = append(dirs, filepath.Dir(Path()))
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	return uniqueDirs(dirs)
}

// ClientAppDirs returns the directories to search for a .env file for the agent-side
// tools: the working directory first, then the directory of the running binary.
func ClientAppDirs() []string {
	dirs := make([]string, 0, 2)
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	return uniqueDirs(dirs)
}

func uniqueDirs(dirs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}
