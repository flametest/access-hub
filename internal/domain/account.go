package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// Account status values (accounts.status).
const (
	AccountStatusPendingActivation = "pending_activation"
	AccountStatusActive            = "active"
	AccountStatusDisabled          = "disabled"
)

// Account source values (accounts.source).
const (
	AccountSourceInvite      = "invite"
	AccountSourceProvisioned = "provisioned"
)

// Grant effect values (role_resources.effect / account_grants.effect). deny
// is reserved for M6; M1-M3 always store allow.
const (
	GrantEffectAllow = "allow"
	GrantEffectDeny  = "deny"
)

// Account is a workspace (per-app) account: independent password + roles,
// structurally bound to exactly one primary identity.
type Account struct {
	id           string
	identityID   string
	appID        string
	email        string
	username     *string
	passwordHash string
	displayName  *string
	status       string
	source       string
	lastLoginAt  *time.Time
	createdAt    time.Time
}

func NewAccount(identityID, appID, email, passwordHash, source string) *Account {
	return &Account{
		identityID:   identityID,
		appID:        appID,
		email:        email,
		passwordHash: passwordHash,
		status:       AccountStatusPendingActivation,
		source:       source,
	}
}

func NewAccountFromDO(do *model.Account) *Account {
	return &Account{
		id:           do.Id,
		identityID:   do.IdentityID,
		appID:        do.AppID,
		email:        do.Email,
		username:     do.Username,
		passwordHash: derefString(do.PasswordHash),
		displayName:  do.DisplayName,
		status:       do.Status,
		source:       do.Source,
		lastLoginAt:  do.LastLoginAt,
		createdAt:    do.CreatedAt,
	}
}

func (a *Account) ToDO() *model.Account {
	var hash *string
	if a.passwordHash != "" {
		h := a.passwordHash
		hash = &h
	}
	return &model.Account{
		BasePostgres: vgorm.BasePostgres{Id: a.id},
		IdentityID:   a.identityID,
		AppID:        a.appID,
		Email:        a.email,
		Username:     a.username,
		PasswordHash: hash,
		DisplayName:  a.displayName,
		Status:       a.status,
		Source:       a.source,
		LastLoginAt:  a.lastLoginAt,
	}
}

// derefString maps a nullable string to "" (empty password hash = no
// password set).
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// CanLogin reports whether the account may perform a direct (per-app) login.
func (a *Account) CanLogin() bool {
	return a.status == AccountStatusActive
}

// Activate transitions pending_activation -> active (after the password is
// set via the activation flow).
func (a *Account) Activate() error {
	if a.status != AccountStatusPendingActivation {
		return verrors.ConflictError(fmt.Sprintf("account %s not pending_activation (current: %s)", a.id, a.status))
	}
	a.status = AccountStatusActive
	return nil
}

// Disable transitions active|pending_activation -> disabled.
func (a *Account) Disable() error {
	if a.status == AccountStatusDisabled {
		return verrors.ConflictError(fmt.Sprintf("account %s already disabled", a.id))
	}
	a.status = AccountStatusDisabled
	return nil
}

func (a *Account) ID() string              { return a.id }
func (a *Account) IdentityID() string      { return a.identityID }
func (a *Account) AppID() string           { return a.appID }
func (a *Account) Email() string           { return a.email }
func (a *Account) Username() *string       { return a.username }
func (a *Account) PasswordHash() string    { return a.passwordHash }
func (a *Account) DisplayName() *string    { return a.displayName }
func (a *Account) Status() string          { return a.status }
func (a *Account) Source() string          { return a.source }
func (a *Account) LastLoginAt() *time.Time { return a.lastLoginAt }
func (a *Account) CreatedAt() time.Time    { return a.createdAt }

func (a *Account) SetIdentityID(v string)       { a.identityID = v }
func (a *Account) SetEmail(v string)            { a.email = v }
func (a *Account) SetUsername(v *string)        { a.username = v }
func (a *Account) SetPasswordHash(v string)     { a.passwordHash = v }
func (a *Account) SetDisplayName(v *string)     { a.displayName = v }
func (a *Account) SetLastLoginAt(at *time.Time) { a.lastLoginAt = at }
