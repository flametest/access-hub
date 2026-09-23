package crypt

import (
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	const key = "unit-test-passphrase"
	sealed, err := Seal(key, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.HasPrefix(sealed, "enc:v1:") || sealed == "JBSWY3DPEHPK3PXP" {
		t.Fatalf("sealed value must be prefixed ciphertext: %q", sealed)
	}
	opened, err := Open(key, sealed)
	if err != nil || opened != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open = %q err = %v", opened, err)
	}
	// Distinct nonces per seal (no deterministic reuse).
	again, _ := Seal(key, "JBSWY3DPEHPK3PXP")
	if again == sealed {
		t.Fatal("seal must randomize the nonce")
	}
}

func TestOpenLegacyPlaintextPassthrough(t *testing.T) {
	opened, err := Open("any-key", "PLAINTEXT-SECRET")
	if err != nil || opened != "PLAINTEXT-SECRET" {
		t.Fatalf("legacy plaintext must pass through: %q %v", opened, err)
	}
}

func TestOpenFailsClosed(t *testing.T) {
	sealed, err := Seal("right-key", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open("wrong-key", sealed); err == nil {
		t.Fatal("wrong key must fail")
	}
	if _, err := Open("", sealed); err == nil {
		t.Fatal("missing key with an encrypted value must fail closed")
	}
	// No key configured: values stay plaintext end to end.
	out, err := Seal("", "PLAINTEXT-SECRET")
	if err != nil || out != "PLAINTEXT-SECRET" {
		t.Fatalf("seal without key must be a no-op: %q %v", out, err)
	}
}
