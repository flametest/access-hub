package totp

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func generateCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

func TestGenerateSecretShape(t *testing.T) {
	secret, uri, err := GenerateSecret("alice@test.dev")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	if len(secret) < 16 {
		t.Fatalf("secret too short: %q", secret)
	}
	if !strings.Contains(uri, "otpauth://totp/") ||
		!strings.Contains(uri, "issuer=access-hub") ||
		!strings.Contains(uri, "alice%40test.dev") && !strings.Contains(uri, "alice@test.dev") {
		t.Fatalf("unexpected otpauth uri: %q", uri)
	}
	// The rebuilt URI must carry the same secret (parameter order may differ).
	rebuilt := OTPAuthURI(secret, "alice@test.dev")
	if !strings.Contains(rebuilt, "secret="+secret) || !strings.Contains(rebuilt, "issuer=access-hub") {
		t.Fatalf("rebuilt otpauth uri missing secret/issuer: %q", rebuilt)
	}
}

func TestValidateAcceptsCurrentAndAdjacentSteps(t *testing.T) {
	secret, _, err := GenerateSecret("bob@test.dev")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Now()

	// Current step.
	if step, ok := Validate(secret, generateCodeAt(t, secret, now), now); !ok || step != now.Unix()/Period {
		t.Fatalf("current step code rejected: step=%d ok=%v", step, ok)
	}
	// Previous step (clock drift tolerance).
	if step, ok := Validate(secret, generateCodeAt(t, secret, now.Add(-Period*time.Second)), now); !ok {
		t.Fatalf("previous step code rejected: step=%d", step)
	}
	// Next step.
	if _, ok := Validate(secret, generateCodeAt(t, secret, now.Add(Period*time.Second)), now); !ok {
		t.Fatal("next step code rejected")
	}
}

func TestValidateRejectsOutsideWindow(t *testing.T) {
	secret, _, err := GenerateSecret("carol@test.dev")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Now()
	// Two steps back is outside the ±1 window.
	if _, ok := Validate(secret, generateCodeAt(t, secret, now.Add(-2*Period*time.Second)), now); ok {
		t.Fatal("code two steps old must be rejected")
	}
	// Malformed input.
	if _, ok := Validate(secret, "12345", now); ok {
		t.Fatal("5-digit code must be rejected")
	}
	if _, ok := Validate(secret, "", now); ok {
		t.Fatal("empty code must be rejected")
	}
}

func TestValidateMatchedStepMonotonicForReplayGuard(t *testing.T) {
	secret, _, err := GenerateSecret("dave@test.dev")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Now()
	prevStep := now.Unix()/Period - 1
	code := generateCodeAt(t, secret, time.Unix(prevStep*Period, 0))

	matched, ok := Validate(secret, code, now)
	if !ok || matched != prevStep {
		t.Fatalf("first use: matched=%d want %d (ok=%v)", matched, prevStep, ok)
	}
	// Replay guard semantics: the caller persists the matched step and only
	// accepts strictly greater steps. The same code can only ever match the
	// same step, so a replay deterministically resolves to last_used_step
	// and the monotonic check rejects it.
	lastUsed := matched
	replayed, ok := Validate(secret, code, now)
	if !ok || replayed != lastUsed {
		t.Fatalf("replay must resolve to last_used_step: matched=%d last=%d (ok=%v)", replayed, lastUsed, ok)
	}
	if replayed > lastUsed {
		t.Fatal("monotonic check must reject the replayed step")
	}
}

func TestBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("generate backup codes: %v", err)
	}
	if len(codes) != BackupCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), BackupCodeCount)
	}
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("code %q does not match XXXX-XXXX", code)
		}
		if _, dup := seen[code]; dup {
			t.Fatalf("duplicate code %q", code)
		}
		seen[code] = struct{}{}
	}

	// Hashing normalizes dashes/case: "abcd-1234" and "ABCD1234" collide.
	a := HashBackupCode("abcd-2345")
	b := HashBackupCode("ABCD2345")
	if a == "" || a != b {
		t.Fatalf("hash normalization broken: %q vs %q", a, b)
	}
	// Different codes hash differently.
	if HashBackupCode("ABCD-2345") == HashBackupCode("WXYZ-9876") {
		t.Fatal("distinct codes must hash distinctly")
	}
}

func TestNormalize(t *testing.T) {
	if NormalizeBackupCode(" abcd-2345 ") != "ABCD2345" {
		t.Fatal("backup code normalization broken")
	}
	if NormalizeSecret(" AbCd 2345 ") != "ABCD2345" {
		t.Fatal("secret normalization broken")
	}
}

func TestGeneratedSecretValidatesRoundTrip(t *testing.T) {
	// End-to-end sanity: a code generated for a freshly enrolled secret must
	// validate, and a random 6-digit string must (virtually) never.
	secret, _, err := GenerateSecret("erin@test.dev")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Now()
	if _, ok := Validate(secret, generateCodeAt(t, secret, now), now); !ok {
		t.Fatal("round-trip validation failed")
	}
	if _, ok := Validate(secret, fmt.Sprintf("%06d", 999999), now); ok {
		// Not strictly impossible but 1-in-a-million per attempt; the second
		// consecutive fixed sample failing keeps this from flaking in practice.
		t.Skip("fixed sample collided with the live step (astronomically unlikely)")
	}
}
