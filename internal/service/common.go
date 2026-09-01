// Package service implements the business logic consumed by the HTTP layer.
// This file holds cross-cutting helpers: hashing, randomness, normalization,
// audit writing and transactional repository bundles.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	log "github.com/flametest/vita/vlog"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// sha256Hex returns the lowercase hex sha256 of s (invitations codes, refresh
// tokens and email codes are all stored hashed).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomToken returns a 256-bit opaque token (base64url, 43 chars) used for
// refresh tokens and invitation codes.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// randomDigits returns a numeric OTP of n digits (6 for email codes).
func randomDigits(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, v.Int64()), nil
}

// randomHex returns a 2*nBytes-long lowercase hex string (the social login
// state token and the one-time login_code are 32-hex = 16 bytes).
func randomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// normalizeEmail trims and lower-cases an email address.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// deriveUniqueUsername generates "user_{rand}" style usernames for
// auto-provisioned identities, retrying until the code is free.
func deriveUniqueUsername(ctx context.Context, userRepo repository.UserRepo) (string, error) {
	for i := 0; i < 20; i++ {
		suffix, err := randomToken()
		if err != nil {
			return "", err
		}
		candidate := "user_" + suffix[:6]
		_, err = userRepo.FindByUsername(ctx, candidate)
		if repository.IsNotFound(err) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("derive unique username: exhausted retries")
}

// auditEvents used across the service layer (audit_logs.action).
const (
	AuditLoginSuccess        = "login_success"
	AuditLoginFailed         = "login_failed"
	AuditLoginLocked         = "login_locked"
	AuditLogout              = "logout"
	AuditPasswordChanged     = "password_changed"
	AuditPasswordReset       = "password_reset"
	AuditAccountActivated    = "account_activated"
	AuditAccountTransferred  = "account_transferred"
	AuditInvitationCreated   = "invitation_created"
	AuditInvitationAccepted  = "invitation_accepted"
	AuditInvitationRevoked   = "invitation_revoked"
	AuditRoleGranted         = "role_granted"
	AuditRoleRevoked         = "role_revoked"
	AuditGrantAdded          = "grant_added"
	AuditGrantRemoved        = "grant_removed"
	AuditResourceSynced      = "resource_synced"
	AuditAdminResourceSynced = "admin_resource_synced"
	AuditTokenReuse          = "token_reuse"
	AuditAccountProvisioned  = "account_provisioned"
	AuditOAuthClientCreated  = "oauth_client_created"
	AuditOAuthClientUpdated  = "oauth_client_updated"
	AuditOAuthClientDeleted  = "oauth_client_deleted"
	// M6 custom ABAC rules.
	AuditCustomRuleCreated = "customrule_created"
	AuditCustomRuleUpdated = "customrule_updated"
	AuditCustomRuleDeleted = "customrule_deleted"
	// M5 social login events.
	AuditSocialLinked   = "social_linked"
	AuditSocialRegister = "social_register"
	AuditSocialUnlinked = "social_unlinked"
)

// Actor types for audit_logs.actor_type.
const (
	ActorIdentity = "identity"
	ActorAccount  = "account"
	ActorSystem   = "system"
)

// writeAudit records a security-relevant event. Best-effort: failures are
// logged and never fail the request.
func writeAudit(
	ctx context.Context,
	c container.Container,
	actorType, actorID string,
	orgID *string,
	action, targetType, targetID string,
	detail map[string]any,
	ip, userAgent string,
) {
	entry := &model.AuditLog{
		ActorType: actorType,
		Action:    action,
	}
	if actorID != "" {
		id := actorID
		entry.ActorID = &id
	}
	if orgID != nil && *orgID != "" {
		org := *orgID
		entry.OrgID = &org
	}
	if targetType != "" {
		tt := targetType
		entry.TargetType = &tt
	}
	if targetID != "" {
		tid := targetID
		entry.TargetID = &tid
	}
	if len(detail) > 0 {
		if raw, err := json.Marshal(detail); err == nil {
			entry.Detail = raw
		}
	}
	if ip != "" {
		v := ip
		entry.IP = &v
	}
	if userAgent != "" {
		v := userAgent
		entry.UserAgent = &v
	}
	if err := c.AuditLogRepo().Create(ctx, entry); err != nil {
		log.Warn().Any("error", err).Any("action", action).Msg("audit log write failed (ignored)")
	}
}

// txRepos bundles repository instances re-wrapped over a transaction so
// multi-table writes are atomic (the repos are plain structs over *gorm.DB).
type txRepos struct {
	users       repository.UserRepo
	accounts    repository.AccountRepo
	orgs        repository.OrgRepo
	orgMembers  repository.OrgMemberRepo
	apps        repository.AppRepo
	resources   repository.ResourceRepo
	roles       repository.RoleRepo
	roleRes     repository.RoleResourceRepo
	accountRole repository.AccountRoleRepo
	grants      repository.AccountGrantRepo
	sessions    repository.SessionRepo
	invitations repository.InvitationRepo
	identities  repository.IdentityRepo
}

func newTxRepos(tx *gorm.DB) *txRepos {
	return &txRepos{
		users:       repository.NewUserRepo(tx),
		accounts:    repository.NewAccountRepo(tx),
		orgs:        repository.NewOrgRepo(tx),
		orgMembers:  repository.NewOrgMemberRepo(tx),
		apps:        repository.NewAppRepo(tx),
		resources:   repository.NewResourceRepo(tx),
		roles:       repository.NewRoleRepo(tx),
		roleRes:     repository.NewRoleResourceRepo(tx),
		accountRole: repository.NewAccountRoleRepo(tx),
		grants:      repository.NewAccountGrantRepo(tx),
		sessions:    repository.NewSessionRepo(tx),
		invitations: repository.NewInvitationRepo(tx),
		identities:  repository.NewIdentityRepo(tx),
	}
}

// runInTx executes fn with transaction-scoped repositories.
func runInTx(c container.Container, fn func(r *txRepos) error) error {
	return c.DB().Transaction(func(tx *gorm.DB) error {
		return fn(newTxRepos(tx))
	})
}

// uuidOrNew returns the id of a freshly created row (rows created inside a
// transaction keep the id set by the caller).
func newID() string { return uuid.NewString() }

// expired reports whether an expires_at pointer is in the past.
func expired(at *time.Time, now time.Time) bool {
	return at != nil && at.Before(now)
}

// nowUTC is the canonical "now" for updates.
func nowUTC() time.Time { return time.Now() }

// jsonMarshal is a small indirection for encoding detail payloads.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// jsonUnmarshal is a small indirection for decoding jsonb columns.
func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// jsonStringsOf decodes a jsonb string array column, tolerating nil input.
func jsonStringsOf(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// WriteSystemAudit records an automated (system actor) event, e.g. the
// startup admin resource sync.
func WriteSystemAudit(ctx context.Context, c container.Container, action string, detail map[string]any) {
	writeAudit(ctx, c, ActorSystem, "", nil, action, "", "", detail, "", "")
}
