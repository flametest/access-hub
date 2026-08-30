package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// User status values (users.status).
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

// User is the primary identity (Company ID). It holds portal credentials and
// profile; business-app permissions live on its workspace accounts.
type User struct {
	id                 string
	username           string
	email              string
	emailVerified      bool
	passwordHash       *string
	nickname           *string
	avatarURL          *string
	status             string
	mustChangePassword bool
	lastLoginAt        *time.Time
	createdAt          time.Time
}

func NewUser(username, email, passwordHash string) *User {
	return &User{
		username:      username,
		email:         email,
		emailVerified: false,
		passwordHash:  strPtr(passwordHash),
		status:        UserStatusActive,
	}
}

func NewUserFromDO(do *model.User) *User {
	return &User{
		id:                 do.Id,
		username:           do.Username,
		email:              do.Email,
		emailVerified:      do.EmailVerified,
		passwordHash:       do.PasswordHash,
		nickname:           do.Nickname,
		avatarURL:          do.AvatarURL,
		status:             do.Status,
		mustChangePassword: do.MustChangePassword,
		lastLoginAt:        do.LastLoginAt,
		createdAt:          do.CreatedAt,
	}
}

func (u *User) ToDO() *model.User {
	return &model.User{
		BasePostgres:       vgorm.BasePostgres{Id: u.id},
		Username:           u.username,
		Email:              u.email,
		EmailVerified:      u.emailVerified,
		PasswordHash:       u.passwordHash,
		Nickname:           u.nickname,
		AvatarURL:          u.avatarURL,
		Status:             u.status,
		MustChangePassword: u.mustChangePassword,
		LastLoginAt:        u.lastLoginAt,
	}
}

// CanPortalLogin reports whether the identity may use the portal password
// login: it must be active and have a password set (auto-provisioned
// identities without a password are rejected and must use email set-password).
func (u *User) CanPortalLogin() bool {
	return u.status == UserStatusActive && u.passwordHash != nil && *u.passwordHash != ""
}

func (u *User) ID() string                  { return u.id }
func (u *User) Username() string            { return u.username }
func (u *User) Email() string               { return u.email }
func (u *User) EmailVerified() bool         { return u.emailVerified }
func (u *User) PasswordHash() *string       { return u.passwordHash }
func (u *User) Nickname() *string           { return u.nickname }
func (u *User) AvatarURL() *string          { return u.avatarURL }
func (u *User) Status() string              { return u.status }
func (u *User) MustChangePassword() bool    { return u.mustChangePassword }
func (u *User) LastLoginAt() *time.Time     { return u.lastLoginAt }
func (u *User) CreatedAt() time.Time        { return u.createdAt }

func (u *User) SetUsername(v string)            { u.username = v }
func (u *User) SetEmail(v string)               { u.email = v }
func (u *User) SetEmailVerified(v bool)         { u.emailVerified = v }
func (u *User) SetPasswordHash(hash *string)    { u.passwordHash = hash }
func (u *User) SetPasswordHashString(hash string) { u.passwordHash = strPtr(hash) }
func (u *User) SetNickname(v *string)           { u.nickname = v }
func (u *User) SetAvatarURL(v *string)          { u.avatarURL = v }
func (u *User) SetMustChangePassword(v bool)    { u.mustChangePassword = v }
func (u *User) SetLastLoginAt(at *time.Time)    { u.lastLoginAt = at }

// Disable transitions active -> disabled.
func (u *User) Disable() error {
	if u.status != UserStatusActive {
		return verrors.ConflictError(fmt.Sprintf("user %s not active (current: %s)", u.id, u.status))
	}
	u.status = UserStatusDisabled
	return nil
}

// Enable transitions disabled -> active.
func (u *User) Enable() error {
	if u.status != UserStatusDisabled {
		return verrors.ConflictError(fmt.Sprintf("user %s not disabled (current: %s)", u.id, u.status))
	}
	u.status = UserStatusActive
	return nil
}

// strPtr returns nil for empty strings, a pointer otherwise. Shared by domain
// entities that map nullable TEXT columns.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
