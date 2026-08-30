package password

import (
	"strings"
	"testing"

	"github.com/flametest/vita/verrors"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	// Low cost keeps the test fast; cost is configurable per environment.
	const cost = 4

	hash, err := Hash("S3curePass!", cost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash %q is not a bcrypt hash", hash)
	}
	// The per-password salt must be embedded: two hashes of the same password
	// differ (no manual salt column needed).
	hash2, err := Hash("S3curePass!", cost)
	if err != nil {
		t.Fatalf("hash twice: %v", err)
	}
	if hash == hash2 {
		t.Fatal("two hashes of the same password should differ (embedded random salt)")
	}
	if err := Verify(hash, "S3curePass!"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := Verify(hash, "wrong"); err == nil {
		t.Fatal("verify wrong password should fail")
	}
}

func TestHashInvalidCost(t *testing.T) {
	if _, err := Hash("S3curePass!", 99); err == nil {
		t.Fatal("hash with out-of-range cost should fail")
	}
}

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"valid", "GoodPass1", false},
		{"valid with symbols", "GoodPass1!", false},
		{"too short", "Ab1defg", true},
		{"too long exceeds bcrypt 72-byte limit", strings.Repeat("aA1", 25), true},
		{"missing digit", "GoodPassword", true},
		{"missing uppercase", "goodpass1", true},
		{"missing lowercase", "GOODPASS1", true},
		{"weak list match exact", "Password1", true},
		{"weak list match case-insensitive", "PASSWORD1", true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePolicy(tc.pw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidatePolicy(%q) error = %v, wantErr %v", tc.pw, err, tc.wantErr)
			}
		})
	}
}

func TestVerifyErrorIsUnauthorized(t *testing.T) {
	hash, err := Hash("S3curePass!", 4)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	err = Verify(hash, "nope")
	var verr *verrors.Error
	if !verrors.As(err, &verr) {
		t.Fatalf("verify mismatch should return a verrors error, got %v", err)
	}
	if verr.ErrCode() != verrors.UnauthorizedCode {
		t.Fatalf("verify mismatch code = %d, want %d", verr.ErrCode(), verrors.UnauthorizedCode)
	}
}

func TestPolicyErrorIsBadRequest(t *testing.T) {
	err := ValidatePolicy("short")
	var verr *verrors.Error
	if !verrors.As(err, &verr) {
		t.Fatalf("policy violation should return a verrors error, got %v", err)
	}
	if verr.ErrCode() != verrors.BadRequestCode {
		t.Fatalf("policy violation code = %d, want %d", verr.ErrCode(), verrors.BadRequestCode)
	}
}
