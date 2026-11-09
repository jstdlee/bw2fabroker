package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DotEnvName is the file name the loader looks for.
const DotEnvName = ".env"

// dotEnvKeyPattern is the set of names a variable may have.
var dotEnvKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadDotEnv reads a .env file and sets the variables in the process environment
// that are not already set. A variable that is already in the environment wins.
// A missing file is not an error: it returns "", 0, nil.
// It returns the path it loaded and how many variables it set.
func LoadDotEnv(path string) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("dotenv %s: %w", path, err)
	}
	count := 0
	for _, kv := range parseDotEnv(string(data)) {
		key, value := kv[0], kv[1]
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return path, count, fmt.Errorf("dotenv %s: set %s: %w", path, key, err)
		}
		count++
	}
	return path, count, nil
}

// LoadDotEnvFrom tries each directory in order and loads the first .env it finds.
// It returns the path it loaded ("" when no file was found) and how many variables it set.
func LoadDotEnvFrom(dirs ...string) (string, int, error) {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, DotEnvName)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", 0, fmt.Errorf("dotenv %s: %w", path, err)
		}
		return LoadDotEnv(path)
	}
	return "", 0, nil
}

// parseDotEnv reads the key/value pairs of a .env file. Lines that are blank,
// comments, or malformed are skipped silently.
func parseDotEnv(content string) [][2]string {
	var pairs [][2]string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = cutDotEnvExport(line)
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !dotEnvKeyPattern.MatchString(key) {
			continue
		}
		pairs = append(pairs, [2]string{key, unquoteDotEnvValue(strings.TrimSpace(line[eq+1:]))})
	}
	return pairs
}

// cutDotEnvExport removes a leading "export " (any case) from a line.
func cutDotEnvExport(line string) string {
	const keyword = "export"
	if len(line) < len(keyword)+1 || !strings.EqualFold(line[:len(keyword)], keyword) {
		return line
	}
	if !isDotEnvSpace(line[len(keyword)]) {
		return line
	}
	return strings.TrimSpace(line[len(keyword):])
}

// isDotEnvSpace reports whether c separates the export keyword from the key.
func isDotEnvSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\v', '\f', '\r':
		return true
	}
	return false
}

// unquoteDotEnvValue strips a matching pair of surrounding quotes. Single quotes
// keep their content as it is; double quotes unescape \n, \t and \r\n.
func unquoteDotEnvValue(value string) string {
	if len(value) < 2 {
		return value
	}
	quote := value[0]
	if quote != '\'' && quote != '"' {
		return value
	}
	if value[len(value)-1] != quote {
		return value
	}
	inner := value[1 : len(value)-1]
	if quote == '\'' {
		return inner
	}
	return unescapeDotEnvDouble(inner)
}

// unescapeDotEnvDouble replaces the escape sequences of a double quoted value.
// Every other backslash stays as it is.
func unescapeDotEnvDouble(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	// \r\n collapses into a single newline. It is handled first so that the \n
	// of the sequence is not expanded on its own; a lone \r stays as it is.
	s = strings.ReplaceAll(s, `\r\n`, "\n")
	var b strings.Builder
	b.Grow(len(s))
	// The loop is explicit because an escape sequence covers two characters.
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
