package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPVector(t *testing.T) {
	// RFC 6238 appendix B, SHA1, secret ASCII "12345678901234567890", T = 59 → 287082.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if !VerifyTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("RFC vector rejected")
	}
	if VerifyTOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("wrong code accepted")
	}
	if VerifyTOTP(secret, "28708", time.Unix(59, 0)) {
		t.Fatal("short code accepted")
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, url, err := NewTOTPSecret()
	if err != nil || !strings.Contains(url, secret) {
		t.Fatal(err, url)
	}
	now := time.Now()
	code, err := totpAt(secret, now)
	if err != nil || !VerifyTOTP(secret, code, now) {
		t.Fatal(code, err)
	}
}
