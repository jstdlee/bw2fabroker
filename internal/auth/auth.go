// Package auth holds the broker's small crypto pieces: the argon2id approval password, signed
// approval links, agent tokens, and request ids.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 second recommended option, with 64 MiB memory).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLen is the shortest approval password the CLI accepts.
const MinPasswordLen = 10

var b64 = base64.RawURLEncoding

// HashPassword returns an encoded argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 {
		return false
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewKey returns n random bytes, hex encoded.
func NewKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewRequestID returns "r_" plus 128 random bits.
func NewRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "r_" + b64.EncodeToString(b), nil
}

// NewAgentToken returns a token for an agent and the hash to store.
func NewAgentToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = "bwb_" + b64.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns the stored form of an agent token.
func HashToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// TokenMatches compares a presented token with a stored hash in constant time.
func TokenMatches(token, storedHash string) bool {
	got := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// Linker signs and checks approval links. A link is the request id plus an expiry, signed with
// HMAC-SHA256. The broker stores nothing for it.
type Linker struct{ key []byte }

// NewLinker builds a Linker from a hex key of at least 32 bytes.
func NewLinker(hexKey string) (*Linker, error) {
	k, err := hex.DecodeString(hexKey)
	if err != nil || len(k) < 32 {
		return nil, errors.New("hmac key must be at least 32 bytes of hex")
	}
	return &Linker{key: k}, nil
}

func (l *Linker) mac(id string, exp int64) []byte {
	h := hmac.New(sha256.New, l.key)
	h.Write([]byte("bw2fabroker/approve/v1\x00"))
	h.Write([]byte(id))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(exp))
	h.Write(e[:])
	return h.Sum(nil)
}

// Sign returns the link token for a request id that expires at exp.
func (l *Linker) Sign(id string, exp time.Time) string {
	e := exp.Unix()
	return id + "." + strconv.FormatInt(e, 10) + "." + b64.EncodeToString(l.mac(id, e))
}

// Errors from Verify.
var (
	ErrBadLink     = errors.New("bad link")
	ErrExpiredLink = errors.New("expired link")
)

// Verify checks a link token and returns its request id.
func (l *Linker) Verify(token string, now time.Time) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrBadLink
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrBadLink
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, l.mac(parts[0], exp)) {
		return "", ErrBadLink
	}
	if now.Unix() > exp {
		return parts[0], ErrExpiredLink
	}
	return parts[0], nil
}
