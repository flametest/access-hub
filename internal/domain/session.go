package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// Session scope values (sessions.scope).
const (
	SessionScopeIdentity = "identity"
	SessionScopeAccount  = "account"
)

// Session is a refresh-token record with in-place rotation.
type Session struct {
	id               string
	userID           string
	scope            string
	accountID        *string
	appID            *string
	refreshTokenHash string
	device           *string
	ip               *string
	lastUsedAt       *time.Time
	rotationCount    int64
	expiresAt        time.Time
	revokedAt        *time.Time
	createdAt        time.Time
}

func NewSession(userID, scope, refreshTokenHash string, expiresAt time.Time) *Session {
	return &Session{
		userID:           userID,
		scope:            scope,
		refreshTokenHash: refreshTokenHash,
		expiresAt:        expiresAt,
	}
}

func NewSessionFromDO(do *model.Session) *Session {
	return &Session{
		id:               do.Id,
		userID:           do.UserID,
		scope:            do.Scope,
		accountID:        do.AccountID,
		appID:            do.AppID,
		refreshTokenHash: do.RefreshTokenHash,
		device:           do.Device,
		ip:               do.IP,
		lastUsedAt:       do.LastUsedAt,
		rotationCount:    do.RotationCount,
		expiresAt:        do.ExpiresAt,
		revokedAt:        do.RevokedAt,
		createdAt:        do.CreatedAt,
	}
}

func (s *Session) ToDO() *model.Session {
	return &model.Session{
		BasePostgres:     vgorm.BasePostgres{Id: s.id},
		UserID:           s.userID,
		Scope:            s.scope,
		AccountID:        s.accountID,
		AppID:            s.appID,
		RefreshTokenHash: s.refreshTokenHash,
		Device:           s.device,
		IP:               s.ip,
		LastUsedAt:       s.lastUsedAt,
		RotationCount:    s.rotationCount,
		ExpiresAt:        s.expiresAt,
		RevokedAt:        s.revokedAt,
	}
}

// IsActive reports whether the session is neither revoked nor expired.
func (s *Session) IsActive(now time.Time) bool {
	return s.revokedAt == nil && now.Before(s.expiresAt)
}

// Rotate performs in-place refresh-token rotation: replaces the stored hash
// and bumps rotation_count. Callers must detect reuse of the previous hash
// before calling Rotate (reuse => revoke the whole session).
func (s *Session) Rotate(newTokenHash string) {
	s.refreshTokenHash = newTokenHash
	s.rotationCount++
}

// Revoke marks the session revoked at the given time. Revoking an already
// revoked session is rejected so callers can detect misuse.
func (s *Session) Revoke(at time.Time) error {
	if s.revokedAt != nil {
		return verrors.ConflictError(fmt.Sprintf("session %s already revoked", s.id))
	}
	s.revokedAt = &at
	return nil
}

func (s *Session) ID() string               { return s.id }
func (s *Session) UserID() string           { return s.userID }
func (s *Session) Scope() string            { return s.scope }
func (s *Session) AccountID() *string       { return s.accountID }
func (s *Session) AppID() *string           { return s.appID }
func (s *Session) RefreshTokenHash() string { return s.refreshTokenHash }
func (s *Session) Device() *string          { return s.device }
func (s *Session) IP() *string              { return s.ip }
func (s *Session) LastUsedAt() *time.Time   { return s.lastUsedAt }
func (s *Session) RotationCount() int64     { return s.rotationCount }
func (s *Session) ExpiresAt() time.Time     { return s.expiresAt }
func (s *Session) RevokedAt() *time.Time    { return s.revokedAt }
func (s *Session) CreatedAt() time.Time     { return s.createdAt }

func (s *Session) SetScope(v string) error {
	if v != SessionScopeIdentity && v != SessionScopeAccount {
		return verrors.BadRequestError(fmt.Sprintf("invalid session scope %q", v))
	}
	s.scope = v
	return nil
}
func (s *Session) SetAccountID(v *string)       { s.accountID = v }
func (s *Session) SetAppID(v *string)           { s.appID = v }
func (s *Session) SetRefreshTokenHash(v string) { s.refreshTokenHash = v }
func (s *Session) SetDevice(v *string)          { s.device = v }
func (s *Session) SetIP(v *string)              { s.ip = v }
func (s *Session) SetLastUsedAt(v *time.Time)   { s.lastUsedAt = v }
func (s *Session) SetExpiresAt(v time.Time)     { s.expiresAt = v }

// jsonStrings decodes a JSON array of strings, tolerating nil/empty input.
func jsonStrings(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// stringsJSON encodes a string slice as JSON ([] for nil input, matching the
// DB default '[]').
func stringsJSON(in []string) []byte {
	if in == nil {
		in = []string{}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return []byte("[]")
	}
	return raw
}
