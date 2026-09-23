// Package password implements bcrypt-based password hashing and the password
// policy (design.md §7): bcrypt's per-password 128-bit salt is embedded in the
// output hash, so no manual salt pre-concatenation is used or needed.
package password

import (
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/flametest/vita/verrors"
	"golang.org/x/crypto/bcrypt"
)

// MinLength / MaxLength bound the policy. MaxLength is bcrypt's hard input
// limit: longer inputs are rejected outright, never silently truncated.
const (
	MinLength = 8
	MaxLength = 72
)

// weakPasswords is a small built-in deny list (matched lower-cased, whole
// password) rejected in addition to the character-class rules.
var weakPasswords = map[string]struct{}{
	"password":     {},
	"password1":    {},
	"password123":  {},
	"12345678":     {},
	"123456789":    {},
	"1234567890":   {},
	"qwertyuiop":   {},
	"qwerty123":    {},
	"abc12345":     {},
	"abc123456":    {},
	"iloveyou":     {},
	"admin123":     {},
	"admin123456":  {},
	"letmein":      {},
	"letmein123":   {},
	"welcome1":     {},
	"welcome123":   {},
	"monkey123":    {},
	"accesshub":    {},
	"accesshub123": {},
	"changeme":     {},
	"changeme123":  {},
}

// Hash hashes the password with bcrypt at the given cost.
func Hash(pw string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", verrors.InternalServerError(fmt.Sprintf("bcrypt cost %d out of range [%d,%d]", cost, bcrypt.MinCost, bcrypt.MaxCost))
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		return "", verrors.Wrap(err, "hash password")
	}
	return string(hash), nil
}

// Verify reports whether the password matches the stored bcrypt hash
// (constant-time comparison inside bcrypt). Returns nil on success and a
// verrors UnauthorizedError on mismatch.
func Verify(hash, pw string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err != nil {
		return verrors.UnauthorizedError("invalid credentials")
	}
	return nil
}

// dummyVerify state: the bcrypt digest is computed lazily (once per cost)
// and only the comparison repeats per call.
var (
	dummyMu   sync.Mutex
	dummyHash string
	dummyCost int
)

// DummyVerify burns one bcrypt comparison at the given cost. Login paths
// call it for identifiers that do not exist so a missing account is
// indistinguishable from a wrong password by response timing.
func DummyVerify(cost int) {
	dummyMu.Lock()
	if dummyHash == "" || dummyCost != cost {
		h, err := Hash("access-hub timing equalizer", cost)
		if err != nil {
			dummyMu.Unlock()
			return
		}
		dummyHash, dummyCost = h, cost
	}
	h := dummyHash
	dummyMu.Unlock()
	_ = Verify(h, "")
}

// ValidatePolicy enforces the password policy:
//   - length 8..72 (bytes; >72 rejected — bcrypt would truncate, so we refuse)
//   - at least one lowercase, one uppercase and one digit
//   - not in the built-in weak-password list
func ValidatePolicy(pw string) error {
	if len(pw) < MinLength {
		return verrors.BadRequestError(fmt.Sprintf("password must be at least %d characters", MinLength))
	}
	if len(pw) > MaxLength {
		return verrors.BadRequestError(fmt.Sprintf("password must be at most %d characters (bcrypt hard limit, longer passwords are rejected, not truncated)", MaxLength))
	}

	var hasLower, hasUpper, hasDigit bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	missing := make([]string, 0, 3)
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if len(missing) > 0 {
		return verrors.BadRequestError("password must contain " + strings.Join(missing, ", "))
	}

	if _, weak := weakPasswords[strings.ToLower(pw)]; weak {
		return verrors.BadRequestError("password is too common, choose a stronger one")
	}

	return nil
}
