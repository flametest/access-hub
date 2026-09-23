// Package crypt implements application-layer encryption for sensitive
// columns at rest (TOTP secrets today): AES-256-GCM under a key derived
// from the configured passphrase. Values are self-describing
// ("enc:v1:<base64url(nonce|ciphertext)>") so legacy plaintext rows keep
// working and re-encryption can happen lazily on write.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/flametest/vita/verrors"
)

// prefix marks an encrypted value (versioned for future migrations).
const prefix = "enc:v1:"

// Seal encrypts plaintext under the passphrase-derived key. An empty
// passphrase returns the plaintext unchanged (encryption not configured);
// callers store its output verbatim.
func Seal(passphrase, plaintext string) (string, error) {
	if passphrase == "" {
		return plaintext, nil
	}
	gcm, err := cipherOf(passphrase)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("generate nonce: %v", err))
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a Seal-produced value. Values without the prefix are legacy
// plaintext and pass through unchanged; a prefixed value that fails to
// decrypt (wrong key, tampering) is an error — callers must fail closed.
func Open(passphrase, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return sealed, nil
	}
	if passphrase == "" {
		return "", verrors.InternalServerError("encrypted value present but no totpSecretKey configured")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("decode encrypted value: %v", err))
	}
	gcm, err := cipherOf(passphrase)
	if err != nil {
		return "", err
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", verrors.InternalServerError("decrypt value: key mismatch or corrupted data")
	}
	return string(plain), nil
}

// cipherOf derives the AES-256-GCM cipher from the passphrase (sha256 →
// 256-bit key; the config value is a server-side secret, so a plain KDF is
// adequate — there is no low-entropy password to brute force).
func cipherOf(passphrase string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("aes cipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("gcm: %v", err))
	}
	return gcm, nil
}
