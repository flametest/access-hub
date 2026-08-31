package dto

import "time"

// Me is the identity (primary account) profile — the canonical shape returned
// by GET/PATCH /api/v1/me and embedded in the register response.
type Me struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	EmailVerified      bool       `json:"email_verified"`
	Nickname           string     `json:"nickname"`
	AvatarURL          string     `json:"avatar_url"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	TwoFAEnabled       bool       `json:"two_fa_enabled"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at"`
}

// UpdateMeReq is the body of PATCH /api/v1/me. When Password is set,
// CurrentPassword must verify and all other identity sessions are revoked.
type UpdateMeReq struct {
	Nickname        *string `json:"nickname" validate:"omitempty,max=255"`
	AvatarURL       *string `json:"avatar_url" validate:"omitempty,max=1024"`
	Password        string  `json:"password" validate:"omitempty"`
	CurrentPassword string  `json:"current_password" validate:"omitempty"`
}

// MyOrgItem is one entry of GET /api/v1/me/orgs.
type MyOrgItem struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	OrgRole string `json:"org_role"`
}

// WorkspaceItem is one entry of GET /api/v1/me/workspaces (the portal
// workspace selector data source).
type WorkspaceItem struct {
	AccountID   string        `json:"account_id"`
	AppKey      string        `json:"app_key"`
	AppName     string        `json:"app_name"`
	AppLogoURL  string        `json:"app_logo_url"`
	OrgKey      string        `json:"org_key"`
	OrgName     string        `json:"org_name"`
	Email       string        `json:"email"`
	DisplayName string        `json:"display_name"`
	Status      string        `json:"status"`
	Roles       []RoleSummary `json:"roles"`
	LastLoginAt *time.Time    `json:"last_login_at"`
}

// WorkspaceTokenResp is the response of POST /me/workspaces/{id}/token.
type WorkspaceTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	AccountID    string `json:"account_id"`
	AppKey       string `json:"app_key"`
}

// MenuNode is one node of the GET /api/v1/me/menus tree.
type MenuNode struct {
	ID       string      `json:"id"`
	Code     string      `json:"code"`
	Name     string      `json:"name"`
	Path     string      `json:"path"`
	Icon     string      `json:"icon"`
	Sort     int         `json:"sort"`
	Children []*MenuNode `json:"children"`
}

// PermissionsResp is the response of GET /api/v1/me/permissions. Version is
// the app's policy version so callers can cache the code set.
type PermissionsResp struct {
	App         string   `json:"app"`
	Version     int64    `json:"version"`
	Permissions []string `json:"permissions"`
}

// SigninMethod is one entry of GET /api/v1/me/signin-methods.
type SigninMethod struct {
	Type    string `json:"type"`
	Label   string `json:"label"`
	Detail  string `json:"detail"`
	Enabled bool   `json:"enabled"`
}

// SessionItem is one entry of GET /api/v1/me/sessions.
type SessionItem struct {
	ID            string     `json:"id"`
	Scope         string     `json:"scope"`
	AppKey        string     `json:"app_key"`
	Device        string     `json:"device"`
	IP            string     `json:"ip"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	RotationCount int64      `json:"rotation_count"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Current       bool       `json:"current"`
}

// ---------- 2FA self-service ----------

// TwoFAStatusResp is the response of GET /api/v1/me/2fa/status. enabled is
// true only for a confirmed enrollment (an unconfirmed draft reports false).
type TwoFAStatusResp struct {
	Enabled   bool `json:"enabled"`
	Confirmed bool `json:"confirmed"`
}

// TwoFAEnrollResp is the response of POST /api/v1/me/2fa/enroll: the base32
// secret and the otpauth:// URI to render as a QR code. The enrollment stays
// unconfirmed until POST /api/v1/me/2fa/confirm validates one code.
type TwoFAEnrollResp struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauth_uri"`
}

// TwoFAConfirmReq is the body of POST /api/v1/me/2fa/confirm.
type TwoFAConfirmReq struct {
	Code string `json:"code" validate:"required,max=16"`
}

// TwoFAConfirmResp is the response of POST /api/v1/me/2fa/confirm. The
// backup codes are returned in plaintext exactly once.
type TwoFAConfirmResp struct {
	BackupCodes []string `json:"backup_codes"`
}

// TwoFADisableReq is the body of POST /api/v1/me/2fa/disable.
type TwoFADisableReq struct {
	Password string `json:"password" validate:"required"`
}
