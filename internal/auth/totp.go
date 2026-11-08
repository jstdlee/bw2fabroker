package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP is the authenticator code the approval page asks for when an item is tagged 2FA.
// SHA1, 6 digits, 30 second steps, which is what authenticator apps produce.

const totpStep = 30 * time.Second

// NewTOTPSecret returns a base32 secret and the otpauth URL for an authenticator app.
func NewTOTPSecret() (secret, url string, err error) {
	raw := make([]byte, 20)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	url = fmt.Sprintf("otpauth://totp/bw2fabroker:approval?secret=%s&issuer=bw2fabroker&period=30&digits=6", secret)
	return secret, url, nil
}

// VerifyTOTP accepts the current code and one step either side.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, d := range code {
		if d < '0' || d > '9' {
			return false
		}
	}
	ok := false
	for _, skew := range []int{-1, 0, 1} {
		got, err := totpAt(secret, now.Add(time.Duration(skew)*totpStep))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(got), []byte(code)) {
			ok = true
		}
	}
	return ok
}

func totpAt(secret string, now time.Time) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/int64(totpStep.Seconds())))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%1_000_000), nil
}
