// 2FA (TOTP) shared helpers and self-service operations. The login challenge
// lives in auth_service (Login/Login2FA); this file owns the enrollment
// state machine shared by both (design.md §12 M4: 2FA is an optional
// enhancement for identity/portal logins only — account direct-login never
// challenges).
package service

import (
	"context"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/internal/infra/totp"
	"github.com/flametest/vita/verrors"
)

// Audit events for the 2FA lifecycle (audit_logs.action).
const (
	AuditTwoFAEnabled  = "twofa_enabled"
	AuditTwoFADisabled = "twofa_disabled"
	AuditTwoFALogin    = "twofa_login"
)

// twoFAConfirmed reports whether the identity has a CONFIRMED TOTP
// enrollment (an unconfirmed draft does not challenge logins).
func twoFAConfirmed(ctx context.Context, c container.Container, userID string) bool {
	row, err := c.TOTPSecretRepo().FindByUserID(ctx, userID)
	return err == nil && row != nil && row.Confirmed
}

// backupHashes decodes the stored backup-code hashes.
func backupHashes(row *model.TOTPSecret) []string {
	return jsonStringsOf(row.BackupCodes)
}

// consumeTwoFACode validates the presented code against the enrollment and
// applies the one-time semantics:
//   - 6 digits -> TOTP validation with a ±1 step window; the matched step is
//     persisted (last_used_step) and equal/older steps are rejected.
//   - anything else -> single-use backup code (dashes normalized away; the
//     matching hash is removed from the stored set).
func consumeTwoFACode(ctx context.Context, c container.Container, row *model.TOTPSecret, code string) error {
	code = strings.TrimSpace(code)
	if isSixDigits(code) {
		matched, ok := totp.Validate(row.Secret, code, time.Now())
		if !ok || matched <= row.LastUsedStep {
			return verrors.ForbiddenError("invalid verification code")
		}
		if err := c.TOTPSecretRepo().UpdateFields(ctx, row.Id, map[string]any{"last_used_step": matched}); err != nil {
			return verrors.Wrap(err, "record totp step")
		}
		return nil
	}
	hash := totp.HashBackupCode(code)
	hashes := backupHashes(row)
	for i, existing := range hashes {
		if existing == hash {
			remaining := append(hashes[:i:i], hashes[i+1:]...)
			if err := c.TOTPSecretRepo().UpdateFields(ctx, row.Id, map[string]any{"backup_codes": encodeJSONStrings(remaining)}); err != nil {
				return verrors.Wrap(err, "consume backup code")
			}
			return nil
		}
	}
	return verrors.ForbiddenError("invalid verification code")
}

// isSixDigits reports whether s is exactly six ASCII digits (TOTP shape).
func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// encodeJSONStrings marshals a string slice as jsonb ([] for nil, matching
// the DB default).
func encodeJSONStrings(in []string) []byte {
	if in == nil {
		return []byte("[]")
	}
	raw, err := jsonMarshal(in)
	if err != nil {
		return []byte("[]")
	}
	return raw
}

// ---------- self-service (identity token required) ----------

// LookupTwoFAStatus returns the caller's enrollment state. enabled is true only
// for a confirmed enrollment.
func LookupTwoFAStatus(ctx context.Context, c container.Container, userID string) (enabled, confirmed bool, err error) {
	row, err := c.TOTPSecretRepo().FindByUserID(ctx, userID)
	if err != nil {
		if repository.IsNotFound(err) {
			return false, false, nil
		}
		return false, false, verrors.Wrap(err, "load totp enrollment")
	}
	return row.Confirmed, row.Confirmed, nil
}

// StartTwoFAEnroll starts (or restarts) an unconfirmed TOTP enrollment: a fresh
// secret replaces any prior unconfirmed draft. Enabling when already
// confirmed requires /2fa/disable first (409).
func StartTwoFAEnroll(ctx context.Context, c container.Container, userID, email string) (secret, otpauthURI string, err error) {
	row, err := c.TOTPSecretRepo().FindByUserID(ctx, userID)
	if err != nil && !repository.IsNotFound(err) {
		return "", "", verrors.Wrap(err, "load totp enrollment")
	}
	if row != nil && row.Confirmed {
		return "", "", verrors.ConflictError("2fa already enabled, disable it first")
	}
	secret, uri, err := totp.GenerateSecret(email)
	if err != nil {
		return "", "", verrors.InternalServerError(err.Error())
	}
	if _, err := c.TOTPSecretRepo().UpsertDraft(ctx, userID, secret); err != nil {
		return "", "", verrors.Wrap(err, "store totp draft")
	}
	return secret, uri, nil
}

// ConfirmTwoFAEnroll validates a first TOTP code against the draft, flips the
// enrollment to confirmed and returns the 8 plaintext backup codes (shown
// once; only sha256 hashes are stored).
func ConfirmTwoFAEnroll(ctx context.Context, c container.Container, userID, code string) ([]string, error) {
	row, err := c.TOTPSecretRepo().FindByUserID(ctx, userID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("no pending 2fa enrollment")
		}
		return nil, verrors.Wrap(err, "load totp enrollment")
	}
	if row.Confirmed {
		return nil, verrors.ConflictError("2fa already enabled")
	}
	if !isSixDigits(strings.TrimSpace(code)) {
		return nil, verrors.ForbiddenError("invalid verification code")
	}
	if _, ok := totp.Validate(row.Secret, code, time.Now()); !ok {
		return nil, verrors.ForbiddenError("invalid verification code")
	}
	codes, err := totp.GenerateBackupCodes()
	if err != nil {
		return nil, verrors.InternalServerError(err.Error())
	}
	hashes := make([]string, 0, len(codes))
	for _, raw := range codes {
		hashes = append(hashes, totp.HashBackupCode(raw))
	}
	// Note: the confirm code does NOT consume its TOTP step
	// (last_used_step stays 0) so a login completed with the same code in
	// the same 30s window is not falsely rejected as a replay; from the
	// first login/2fa success onwards the replay guard is strict.
	if err := c.TOTPSecretRepo().UpdateFields(ctx, row.Id, map[string]any{
		"confirmed":    true,
		"backup_codes": encodeJSONStrings(hashes),
	}); err != nil {
		return nil, verrors.Wrap(err, "confirm totp enrollment")
	}
	writeAudit(ctx, c, ActorIdentity, userID, nil, AuditTwoFAEnabled, "user", userID,
		map[string]any{"via": "self_enroll"}, "", "")
	return codes, nil
}

// DisableTwoFA removes the enrollment after a password re-check (403 on
// mismatch). Issued mfa challenges die naturally with their short TTL.
func DisableTwoFA(ctx context.Context, c container.Container, userID, pwd string) error {
	user, err := c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return verrors.NotFoundError("identity not found")
	}
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		return verrors.ForbiddenError("password not set")
	}
	if err := password.Verify(*user.PasswordHash, pwd); err != nil {
		// 1403 on mismatch (the credential re-check is an authorization
		// guard, not a login attempt).
		return verrors.ForbiddenError("password mismatch")
	}
	row, err := c.TOTPSecretRepo().FindByUserID(ctx, userID)
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("2fa is not enabled")
		}
		return verrors.Wrap(err, "load totp enrollment")
	}
	if err := c.TOTPSecretRepo().Delete(ctx, row.Id); err != nil {
		return verrors.Wrap(err, "delete totp enrollment")
	}
	writeAudit(ctx, c, ActorIdentity, userID, nil, AuditTwoFADisabled, "user", userID,
		map[string]any{"via": "self_disable"}, "", "")
	return nil
}
