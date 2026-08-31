// Package totp implements the TOTP (RFC 6238) building blocks for the 2FA
// optional enhancement (design.md §12 M4): secret enrollment, code
// validation with a ±1 window, replay protection hooks and single-use backup
// codes. The secret is stored base32; backup codes are stored as sha256 hex
// hashes.
package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// Issuer is the TOTP issuer (and otpauth URI label prefix).
	Issuer = "access-hub"
	// Period is the TOTP step length in seconds.
	Period = 30
	// Skew is the number of steps accepted on either side of now (±1).
	Skew = 1
	// BackupCodeCount is the number of single-use recovery codes generated
	// at confirm time.
	BackupCodeCount = 8
)

// digits/algorithm mirror the defaults of totp.Generate (6 digits, SHA1) so
// authenticator-app QR codes and our validator agree.
var digits = otp.DigitsSix

// GenerateSecret creates a fresh base32 TOTP secret for the identity and
// returns it together with the otpauth:// URI for the QR code (account name
// = the identity's email).
func GenerateSecret(email string) (secret, otpauthURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: email,
		Period:      Period,
		Digits:      digits,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// OTPAuthURI rebuilds the otpauth:// enrollment URI from a stored secret
// (used when re-displaying a draft's QR code without regenerating).
func OTPAuthURI(secret, email string) string {
	label := fmt.Sprintf("%s:%s", Issuer, email)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		label, secret, Issuer, digits.Length(), Period)
}

// stepOf returns the TOTP step index of t.
func stepOf(t time.Time) int64 { return t.Unix() / Period }

// Validate checks a 6-digit TOTP code against the secret with a ±1 step
// window and returns the matched step (0 when the code is invalid). Callers
// persist the matched step and reject equal/older steps (replay guard).
func Validate(secret, code string, now time.Time) (matchedStep int64, ok bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}
	opts := totp.ValidateOpts{
		Period:    Period,
		Skew:      0, // the window below is implemented by this loop
		Digits:    digits,
		Algorithm: otp.AlgorithmSHA1,
	}
	center := stepOf(now)
	// Test steps oldest-first so the returned matched step is deterministic
	// (and replay detection keeps the highest accepted step).
	for offset := -int64(Skew); offset <= int64(Skew); offset++ {
		step := center + offset
		valid, err := totp.ValidateCustom(code, secret, time.Unix(step*Period, 0), opts)
		if err == nil && valid {
			return step, true
		}
	}
	return 0, false
}

// GenerateBackupCodes returns 8 single-use recovery codes formatted
// XXXX-XXXX, drawn from an unambiguous 32-char alphabet via crypto/rand.
func GenerateBackupCodes() ([]string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, 0, BackupCodeCount)
	for i := 0; i < BackupCodeCount; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate backup code: %w", err)
		}
		for j, b := range buf {
			buf[j] = alphabet[int(b)%len(alphabet)]
		}
		codes = append(codes, fmt.Sprintf("%s-%s", buf[:4], buf[4:]))
	}
	return codes, nil
}

// NormalizeBackupCode canonicalizes a user-entered backup code: separators
// dropped, upper-cased, trimmed.
func NormalizeBackupCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized
}

// HashBackupCode returns the sha256 hex hash of the normalized backup code
// (the stored form).
func HashBackupCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeBackupCode(code)))
	return hex.EncodeToString(sum[:])
}

// NormalizeSecret canonicalizes a user-entered secret (authenticator apps
// may render it with spaces): upper-case, separators dropped.
func NormalizeSecret(secret string) string {
	s := strings.ToUpper(strings.TrimSpace(secret))
	s = strings.ReplaceAll(s, " ", "")
	return s
}
