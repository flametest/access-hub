package model

import (
	"time"

	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// OAuth client types (oauth_clients.client_type).
const (
	OAuthClientTypeConfidential = "confidential"
	OAuthClientTypePublic       = "public"
)

// OAuth client statuses (oauth_clients.status).
const (
	OAuthClientStatusActive   = "active"
	OAuthClientStatusDisabled = "disabled"
)

// OAuth client grant types (oauth_clients.grant_types entries).
const (
	OAuthGrantAuthorizationCode = "authorization_code"
	OAuthGrantRefreshToken      = "refresh_token"
	OAuthGrantClientCredentials = "client_credentials"
)

// OAuthClient is an OIDC relying-party registration owned by one app. The
// secret is stored hashed (sha256) and shown in plaintext only once, in the
// create response. Public clients (SPA/native) have no secret and MUST use
// PKCE.
type OAuthClient struct {
	vgorm.BasePostgres
	AppID        string         `gorm:"column:app_id"`
	Name         string         `gorm:"column:name"`
	ClientType   string         `gorm:"column:client_type"`
	SecretHash   *string        `gorm:"column:secret_hash"`
	GrantTypes   datatypes.JSON `gorm:"column:grant_types"`
	RedirectURIs datatypes.JSON `gorm:"column:redirect_uris"`
	Scopes       datatypes.JSON `gorm:"column:scopes"`
	Status       string         `gorm:"column:status"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

// OAuthRefreshToken is a refresh token issued by the OAuth2 token endpoint.
// Rotation is in-place (same row: new token_hash, rotation_count++); reuse of
// a replaced hash revokes the whole family (every token of that client).
type OAuthRefreshToken struct {
	vgorm.BasePostgres
	ClientID      string     `gorm:"column:client_id"`
	UserID        *string    `gorm:"column:user_id"`    // identity subject (authorization_code flows)
	AccountID     *string    `gorm:"column:account_id"` // resolved account subject
	TokenHash     string     `gorm:"column:token_hash"`
	Scope         string     `gorm:"column:scope"`
	RotationCount int64      `gorm:"column:rotation_count"`
	LastUsedAt    *time.Time `gorm:"column:last_used_at"`
	ExpiresAt     time.Time  `gorm:"column:expires_at"`
	RevokedAt     *time.Time `gorm:"column:revoked_at"`
}

func (OAuthRefreshToken) TableName() string { return "oauth_refresh_tokens" }
